#!/usr/bin/env python3
"""Murther BETA authentication manager: issue, revoke, export.

One unique 6-digit code per person (000000-999999, leading zeros allowed).
Only salted SHA-256 hashes ever leave this PC — plain codes live only in the
private registry file beta_codes.json (same folder, NEVER commit/publish it).

Typical workflow (all from this folder):
    python gen_beta_code.py --issue Alice        # new code for Alice, prints it once
    python gen_beta_code.py --export             # sync .js allowlist + beta_auth.json
    git add murther.user.beta.js beta_auth.json  # + commit + push
    # testers' Tampermonkey auto-updates the script from the raw GitHub URL,
    # and revocation below takes effect IMMEDIATELY via beta_auth.json:
    python gen_beta_code.py --revoke Alice       # or --revoke 042918 / <hash>
    python gen_beta_code.py --export             # then commit + push again

Release a new client version (pill shows BETA vX.Y.Z automatically):
    python gen_beta_code.py --bump-version 0.0.2 --min-version 0.0.2
    python gen_beta_code.py --export             # then commit + push
"""
import argparse
import datetime
import hashlib
import json
import re
import secrets
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTRY = HERE / "beta_codes.json"   # PRIVATE — your PC only, gitignored
JS_FILE = HERE / "murther.user.beta.js"
AUTH_FILE = HERE / "beta_auth.json"   # PUBLIC — commit this (hashes only)
SALT_BYTES = 32  # 256-bit salt, hex-encoded (64 chars)


def new_salt() -> str:
    return secrets.token_hex(SALT_BYTES)


def new_code(existing: set) -> str:
    # Full 000000-999999 range, cryptographically secure, zero-padded, unique.
    while True:
        c = f"{secrets.randbelow(1_000_000):06d}"
        if c not in existing:
            return c


def digest(salt: str, code: str) -> str:
    if len(code) != 6 or not code.isdigit():
        raise ValueError(f"code must be 6 digits, got {code!r}")
    return hashlib.sha256((salt + code).encode("utf-8")).hexdigest()


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_registry() -> dict:
    if REGISTRY.exists():
        with open(REGISTRY, "r", encoding="utf-8") as f:
            reg = json.load(f)
        reg.setdefault("salt", "")
        reg.setdefault("min_version", "0.0.1")
        reg.setdefault("codes", [])
        return reg
    return {"salt": "", "min_version": "0.0.1", "codes": []}


def save_registry(reg: dict) -> None:
    tmp = REGISTRY.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2)
    tmp.replace(REGISTRY)


def ensure_salt(reg: dict, salt_opt: str) -> str:
    if salt_opt:
        reg["salt"] = salt_opt.strip().lower()
    if not reg["salt"]:
        reg["salt"] = new_salt()
    return reg["salt"]


def find_entry(reg: dict, ident: str):
    ident = ident.strip()
    ident_low = ident.lower()
    for e in reg["codes"]:
        if (e.get("name", "").lower() == ident_low or e.get("code", "") == ident
                or e.get("hash", "").lower() == ident_low):
            return e
    return None


def cmd_issue(args) -> int:
    reg = load_registry()
    salt = ensure_salt(reg, args.salt)
    name = args.issue.strip()
    if not name:
        print("name must not be empty", file=sys.stderr)
        return 2
    if find_entry(reg, name) is not None:
        print(f"{name!r} already exists — use --revoke first to replace.", file=sys.stderr)
        return 2
    existing = {e.get("code", "") for e in reg["codes"]}
    code = new_code(existing)
    h = digest(salt, code)
    reg["codes"].append({"name": name, "code": code, "hash": h,
                         "revoked": False, "issued_at": utcnow(), "revoked_at": ""})
    save_registry(reg)
    print(f"Code for {name} (send privately, shown once): {code}")
    print("Next: python gen_beta_code.py --export  ->  commit + push")
    return 0


def cmd_revoke(args, undo: bool) -> int:
    reg = load_registry()
    ident = args.unrevoke if undo else args.revoke
    e = find_entry(reg, ident)
    if e is None:
        print(f"no entry matches {ident!r} (try --list)", file=sys.stderr)
        return 2
    e["revoked"] = not undo
    e["revoked_at"] = "" if undo else utcnow()
    save_registry(reg)
    verb = "unrevoked" if undo else "REVOKED"
    print(f"{verb}: {e['name']} (hash {e['hash'][:12]}…)")
    if not undo:
        print("This takes effect on next page visit once you --export + push beta_auth.json.")
    print("Next: python gen_beta_code.py --export  ->  commit + push")
    return 0


def cmd_list(args) -> int:
    reg = load_registry()
    if not reg["codes"]:
        print("(registry empty — use --issue <name>)")
        return 0
    for e in reg["codes"]:
        state = "REVOKED" if e.get("revoked") else "active "
        extra = f" code={e['code']}" if args.show_codes else ""
        print(f"[{state}] {e['name']}{extra} hash={e['hash'][:12]}… issued={e.get('issued_at','')}")
    if not args.show_codes:
        print("(add --show-codes to display plain codes)")
    return 0


def sync_js(salt: str, active_hashes: list) -> None:
    """Rewrite the BETA_SALT / BETA_HASHES block in the userscript."""
    src = JS_FILE.read_text(encoding="utf-8")
    lines = ["  var BETA_SALT = \"%s\";" % salt, "  var BETA_HASHES = ["]
    for h in active_hashes:
        lines.append("    \"%s\"," % h)
    lines.append("  ];")
    block = "\n".join(lines)
    pat = re.compile(r'  var BETA_SALT = ".*?";\n  var BETA_HASHES = \[\n(?:.*?\n)*?  \];', re.DOTALL)
    new_src, n = pat.subn(block, src, count=1)
    if n != 1:
        print("ERROR: BETA_SALT/BETA_HASHES block not found in .js — aborting.", file=sys.stderr)
        sys.exit(1)
    JS_FILE.write_text(new_src, encoding="utf-8")


def write_auth(salt: str, revoked: list, min_version: str, n_active: int) -> None:
    payload = {"v": 1, "salt": salt, "revoked": revoked,
               "min_version": min_version, "updated_at": utcnow(), "count_active": n_active}
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def cmd_export(args) -> int:
    reg = load_registry()
    if args.salt:
        reg["salt"] = args.salt.strip().lower()
        save_registry(reg)
    if not reg.get("salt"):
        print("registry has no salt yet — use --issue first.", file=sys.stderr)
        return 2
    if args.min_version:
        reg["min_version"] = args.min_version.strip()
        save_registry(reg)
    salt = reg["salt"]
    active = sorted(e["hash"] for e in reg["codes"] if not e.get("revoked"))
    revoked = sorted(e["hash"] for e in reg["codes"] if e.get("revoked"))
    # Safety: embedded hashes must be verifiable against the registry salt.
    sync_js(salt, active)
    write_auth(salt, revoked, reg.get("min_version", "0.0.1"), len(active))
    print(f"Exported: {len(active)} active, {len(revoked)} revoked, "
          f"salt={salt[:12]}…, min_version={reg.get('min_version')}")
    print("Next: git add murther.user.beta.js beta_auth.json -> commit -> push.")
    print("Revocation is live as soon as beta_auth.json is pushed (no script update needed).")
    return 0


def cmd_bump(args) -> int:
    src = JS_FILE.read_text(encoding="utf-8")
    new_src, n = re.subn(r"(// @version\s+)[0-9][\w.\-]*", r"\g<1>" + args.bump_version.strip(), src, count=1)
    if n != 1:
        print("ERROR: @version header not found.", file=sys.stderr)
        return 1
    JS_FILE.write_text(new_src, encoding="utf-8")
    if args.min_version:
        reg = load_registry()
        reg["min_version"] = args.min_version.strip()
        save_registry(reg)
        print(f"min_version set to {reg['min_version']} (enforced via beta_auth.json on --export)")
    print(f"@version bumped to {args.bump_version.strip()} (pill shows BETA v{args.bump_version.strip()})")
    return 0


def cmd_quick(args) -> int:
    """Legacy: print throwaway codes + snippet without touching the registry."""
    salt = args.salt.strip().lower() or new_salt()
    codes, seen = [], set()
    while len(codes) < args.count:
        c = new_code(seen)
        seen.add(c)
        codes.append(c)
    print("=== KEEP PRIVATE (not in registry — prefer --issue) ===")
    for c in codes:
        print(c)
    print()
    print("=== JS snippet ===")
    print(f'var BETA_SALT = "{salt}";')
    print("var BETA_HASHES = [")
    for c in codes:
        print(f'  "{digest(salt, c)}",')
    print("];")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Murther BETA auth manager (issue / revoke / export)")
    ap.add_argument("--issue", metavar="NAME", default="", help="issue a unique code to NAME")
    ap.add_argument("--revoke", metavar="NAME|CODE|HASH", default="", help="revoke someone's access")
    ap.add_argument("--unrevoke", metavar="NAME|CODE|HASH", default="", help="restore revoked access")
    ap.add_argument("--list", action="store_true", help="list registry entries")
    ap.add_argument("--show-codes", action="store_true", help="with --list, show plain codes")
    ap.add_argument("--export", action="store_true", help="sync .js allowlist + write beta_auth.json")
    ap.add_argument("--bump-version", metavar="X.Y.Z", default="", help="set @version header in .js")
    ap.add_argument("--min-version", default="", help="with --export/--bump-version: oldest client allowed")
    ap.add_argument("--count", type=int, default=0, help="legacy quick-generate N codes (no registry)")
    ap.add_argument("--salt", default="", help="override registry salt")
    ap.add_argument("--verify", default="", help="verify a 6-digit code against --salt + --expect")
    ap.add_argument("--expect", default="", help="expected hash for --verify")
    args = ap.parse_args()

    if args.verify:
        if not args.salt or not args.expect:
            print("need --salt and --expect with --verify", file=sys.stderr)
            return 2
        got = digest(args.salt, args.verify)
        ok = secrets.compare_digest(got, args.expect.lower())
        print("MATCH" if ok else "NO MATCH")
        print(got)
        return 0 if ok else 1
    if args.issue:
        return cmd_issue(args)
    if args.revoke:
        return cmd_revoke(args, undo=False)
    if args.unrevoke:
        return cmd_revoke(args, undo=True)
    if args.list:
        return cmd_list(args)
    if args.bump_version:
        return cmd_bump(args)
    if args.export:
        return cmd_export(args)
    if args.count:
        if not (1 <= args.count <= 1000):
            print("--count must be 1..1000", file=sys.stderr)
            return 2
        return cmd_quick(args)
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
