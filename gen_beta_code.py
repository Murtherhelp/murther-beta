#!/usr/bin/env python3
"""Murther BETA authentication manager: issue, revoke, export.

One unique 6-digit code per person (000000-999999, leading zeros allowed).
Only salted SHA-256 hashes ever leave this PC — plain codes live only in the
private registry file beta_codes.json (same folder, NEVER commit/publish it).

Typical workflow (all from this folder):
    python gen_beta_code.py --issue Alice        # new code for Alice, logged in beta_codes.txt
    python gen_beta_code.py --export             # sync .js allowlist + URLs + beta_auth.json + txt
    # re-obfuscate source -> obfuscated build, then:
    git add murther.user.beta.obfuscated.js beta_auth.json  # + commit + push
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
CODES_TXT = HERE / "beta_codes.txt"   # PRIVATE — plain codes, gitignored
JS_FILE = HERE / "murther.user.beta.js"          # readable source (local only)
OBF_FILE = HERE / "murther.user.beta.obfuscated.js"  # published build (public)
AUTH_FILE = HERE / "beta_auth.json"   # PUBLIC — commit this (hashes only)
SALT_BYTES = 32  # 256-bit salt, hex-encoded (64 chars)

# Single source of truth for the published URLs. Both the source and the
# obfuscated build carry the SAME @updateURL/@downloadURL (pointing at the
# published obfuscated file), so Tampermonkey updates work no matter what.
# --export / --sync-urls rewrite these lines in both files automatically.
GH_USER = "Murtherhelp"
GH_REPO = "murther-beta"
GH_BRANCH = "main"
PUB_FILE = "murther.user.beta.obfuscated.js"


def raw_url(path: str) -> str:
    return f"https://raw.githubusercontent.com/{GH_USER}/{GH_REPO}/{GH_BRANCH}/{path}"


def update_url() -> str:
    return raw_url(PUB_FILE)


def auth_url() -> str:
    return raw_url("beta_auth.json")


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


def write_codes_txt(reg: dict) -> None:
    """Refresh the private ledger: active (non-revoked) names + codes only."""
    active = sorted((e for e in reg["codes"] if not e.get("revoked")),
                    key=lambda e: e.get("name", "").lower())
    with open(CODES_TXT, "w", encoding="utf-8") as f:
        f.write("# Murther BETA codes — PRIVATE. Do NOT share, commit or publish.\n")
        f.write(f"# Updated {utcnow()} — {len(active)} active code(s)."
                " Revoked codes are NOT listed here.\n")
        for e in active:
            f.write(f"{e['name']}: {e['code']}\n")


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
    write_codes_txt(reg)
    print(f"Code for {name} (send privately, also logged in beta_codes.txt): {code}")
    print("Next: python gen_beta_code.py --export  ->  re-obfuscate  ->  commit + push")
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
    write_codes_txt(reg)
    verb = "unrevoked" if undo else "REVOKED"
    print(f"{verb}: {e['name']} (hash {e['hash'][:12]}...)")
    if not undo:
        print("This takes effect on next page visit once you --export + push beta_auth.json.")
    print("Next: python gen_beta_code.py --export  ->  re-obfuscate  ->  commit + push")
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
    """Rewrite the BETA_SALT / BETA_HASHES block in the source userscript."""
    src = JS_FILE.read_text(encoding="utf-8")
    lines = ["  var BETA_SALT = \"%s\";" % salt, "  var BETA_HASHES = ["]
    for h in active_hashes:
        lines.append("    \"%s\"," % h)
    lines.append("  ];")
    block = "\n".join(lines)
    pat = re.compile(r'  var BETA_SALT = ".*?";\n  var BETA_HASHES = \[(?:[^\]]*?)\];', re.DOTALL)
    new_src, n = pat.subn(block, src, count=1)
    if n != 1:
        print("ERROR: BETA_SALT/BETA_HASHES block not found in .js — aborting.", file=sys.stderr)
        sys.exit(1)
    JS_FILE.write_text(new_src, encoding="utf-8")


def sync_urls() -> None:
    """Connect @updateURL/@downloadURL in BOTH files to the published build.

    Only the plain-text ==UserScript== header is touched (Tampermonkey requires
    it readable anyway), so this is safe on the obfuscated file. The obfuscated
    BODY keeps whatever BETA_AUTH_URL was baked in at obfuscation time — that
    one comes from the source, so re-obfuscate after source changes.
    Returns (source_ok, obf_ok).
    """
    url = update_url()
    n_ok = 0
    for path, with_auth in ((JS_FILE, True), (OBF_FILE, False)):
        if not path.exists():
            print(f"skip {path.name}: file not found")
            continue
        src = path.read_text(encoding="utf-8")
        head_end = src.find("==/UserScript==")
        if head_end < 0:
            print(f"ERROR: userscript header not found in {path.name} — skipped.", file=sys.stderr)
            continue
        head, tail = src[:head_end], src[head_end:]
        head2, n1 = re.subn(r"(// @updateURL\s+)\S+", r"\g<1>" + url, head, count=1)
        head2, n2 = re.subn(r"(// @downloadURL\s+)\S+", r"\g<1>" + url, head2, count=1)
        if n1 != 1 or n2 != 1:
            print(f"ERROR: @updateURL/@downloadURL lines not found in {path.name} — skipped.",
                  file=sys.stderr)
            continue
        out = head2 + tail
        if with_auth:
            out2, na = re.subn(r'var BETA_AUTH_URL = ".*?";',
                               f'var BETA_AUTH_URL = "{auth_url()}";', out, count=1)
            if na != 1:
                print(f"ERROR: BETA_AUTH_URL not found in {path.name} — skipped.", file=sys.stderr)
                continue
            out = out2
        path.write_text(out, encoding="utf-8")
        print(f"URLs synced in {path.name} -> {url}")
        n_ok += 1
    return n_ok


def cmd_sync_urls(args) -> int:
    sync_urls()
    return 0


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
    sync_urls()
    write_auth(salt, revoked, reg.get("min_version", "0.0.1"), len(active))
    write_codes_txt(reg)
    print(f"Exported: {len(active)} active, {len(revoked)} revoked, "
          f"salt={salt[:12]}..., min_version={reg.get('min_version')}")
    print("Next: re-obfuscate murther.user.beta.js -> murther.user.beta.obfuscated.js,")
    print("then: git add murther.user.beta.obfuscated.js beta_auth.json -> commit -> push.")
    print("(The source .js stays local/gitignored; revocation goes live once")
    print("beta_auth.json is pushed - no script update needed for that.)")
    return 0


def bump_version_in(path: Path, ver: str) -> bool:
    """Set the // @version header line. Header-only: safe on both files."""
    src = path.read_text(encoding="utf-8")
    new_src, n = re.subn(r"(// @version\s+)[0-9][\w.\-]*", r"\g<1>" + ver, src, count=1)
    if n != 1:
        print(f"ERROR: @version header not found in {path.name}.", file=sys.stderr)
        return False
    path.write_text(new_src, encoding="utf-8")
    print(f"@version {ver} set in {path.name}")
    return True


def cmd_bump(args) -> int:
    ver = args.bump_version.strip()
    ok = bump_version_in(JS_FILE, ver)
    if OBF_FILE.exists():
        ok = bump_version_in(OBF_FILE, ver) and ok
    else:
        print("note: obfuscated build not found — bumped source only; re-obfuscate to carry it over.")
    if not ok:
        return 1
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
    ap.add_argument("--export", action="store_true", help="sync .js allowlist + URLs + write beta_auth.json + codes txt")
    ap.add_argument("--sync-urls", action="store_true", help="rewrite @updateURL/@downloadURL in both .js files")
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
    if args.sync_urls:
        return cmd_sync_urls(args)
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
