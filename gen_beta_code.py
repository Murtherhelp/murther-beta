#!/usr/bin/env python3
"""Murther BETA authentication manager: issue, revoke, export.

One unique 6-digit code per person (000000-999999, leading zeros allowed).
Only salted SHA-256 hashes ever leave this PC - plain codes live only in the
private registry file beta_codes.json (same folder, NEVER commit/publish it).

Typical workflow (all from this folder):
    python gen_beta_code.py                 # interactive panel (numbered menu)
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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTRY = HERE / "beta_codes.json"   # PRIVATE - your PC only, gitignored
CODES_TXT = HERE / "beta_codes.txt"   # PRIVATE - plain codes, gitignored
JS_FILE = HERE / "murther.user.beta.js"          # readable source (local only)
OBF_FILE = HERE / "murther.user.beta.obfuscated.js"  # published build (public)
AUTH_FILE = HERE / "beta_auth.json"   # PUBLIC - commit this (hashes only)
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
        f.write("# Murther BETA codes - PRIVATE. Do NOT share, commit or publish.\n")
        f.write(f"# Updated {utcnow()} - {len(active)} active code(s)."
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
        print(f"{name!r} already exists - use --revoke first to replace.", file=sys.stderr)
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
        print("(registry empty - use --issue <name>)")
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
        print("ERROR: BETA_SALT/BETA_HASHES block not found in .js - aborting.", file=sys.stderr)
        sys.exit(1)
    JS_FILE.write_text(new_src, encoding="utf-8")


def sync_urls() -> None:
    """Connect @updateURL/@downloadURL in BOTH files to the published build.

    Only the plain-text ==UserScript== header is touched (Tampermonkey requires
    it readable anyway), so this is safe on the obfuscated file. The obfuscated
    BODY keeps whatever BETA_AUTH_URL was baked in at obfuscation time - that
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
            print(f"ERROR: userscript header not found in {path.name} - skipped.", file=sys.stderr)
            continue
        head, tail = src[:head_end], src[head_end:]
        head2, n1 = re.subn(r"(// @updateURL\s+)\S+", r"\g<1>" + url, head, count=1)
        head2, n2 = re.subn(r"(// @downloadURL\s+)\S+", r"\g<1>" + url, head2, count=1)
        if n1 != 1 or n2 != 1:
            print(f"ERROR: @updateURL/@downloadURL lines not found in {path.name} - skipped.",
                  file=sys.stderr)
            continue
        out = head2 + tail
        if with_auth:
            out2, na = re.subn(r'var BETA_AUTH_URL = ".*?";',
                               f'var BETA_AUTH_URL = "{auth_url()}";', out, count=1)
            if na != 1:
                print(f"ERROR: BETA_AUTH_URL not found in {path.name} - skipped.", file=sys.stderr)
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
        print("registry has no salt yet - use --issue first.", file=sys.stderr)
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
        print("note: obfuscated build not found - bumped source only; re-obfuscate to carry it over.")
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
    print("=== KEEP PRIVATE (not in registry - prefer --issue) ===")
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


# ============================== interactive panel ==============================
# Numbered menu (runs when the script is started with no arguments). Every
# option below reuses the cmd_* backends above, so flags and menu can never
# drift apart. Plain codes are only ever printed at create/verify time.

USE_COLOR = True

_FONT = {
    "A": ["  #  ", " # # ", "#####", "#   #", "#   #"],
    "B": ["#### ", "#   #", "#### ", "#   #", "#### "],
    "C": [" ####", "#    ", "#    ", "#    ", " ####"],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "G": [" ####", "#    ", "# ###", "#   #", " ### "],
    "H": ["#   #", "#   #", "#####", "#   #", "#   #"],
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "U": ["#   #", "#   #", "#   #", "#   #", " ### "],
    " ": ["     ", "     ", "     ", "     ", "     "],
}


def _fig(word: str):
    rows = [""] * 5
    for ch in word.upper():
        g = _FONT.get(ch, _FONT[" "])
        for i in range(5):
            rows[i] += g[i] + "  "
    return [r.rstrip() for r in rows]


def _paint(s: str) -> str:
    if USE_COLOR:
        return "\033[95m" + s + "\033[0m"
    return s


def print_banner() -> None:
    lines = _fig("GEN") + [""] + _fig("MURTHER") + [""] + _fig("BETA CODE")
    width = max(len(r) for r in lines)
    bar = "=" * (width + 4)
    print(_paint(bar))
    for r in lines:
        print(_paint("  " + r.ljust(width)))
    print(_paint(bar))
    print("  Murther BETA authentication manager")
    print()


def _pause() -> None:
    try:
        input("Press Enter to continue... ")
    except (EOFError, KeyboardInterrupt):
        print()


def _ns(**kw):
    from argparse import Namespace
    base = dict(issue="", revoke="", unrevoke="", list=False, show_codes=False,
                export=False, sync_urls=False, bump_version="", min_version="",
                count=0, salt="", verify="", expect="")
    base.update(kw)
    return Namespace(**base)


def _pick(entries, what: str):
    """Numbered picker over registry entries. Returns the entry or None."""
    if not entries:
        print(f"(no {what} entries)")
        return None
    for i, e in enumerate(entries, 1):
        state = "REVOKED" if e.get("revoked") else "active "
        print(f"  {i}. [{state}] {e.get('name', '?')}  hash={e.get('hash', '')[:12]}...")
    print("   0. Cancel")
    try:
        raw = input(f"Pick a {what[:-1]} (number, name, code or hash): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if raw == "0" or not raw:
        return None
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(entries):
            return entries[idx]
        print("Out of range - cancelled.")
        return None
    e = find_entry({"codes": entries}, raw)
    if e is None:
        print(f"no entry matches {raw!r} - cancelled.")
    return e


def _confirm(msg: str) -> bool:
    try:
        return input(msg + " (y/n): ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def menu_create() -> None:
    print_banner()
    print("--- 1. Create a code ---\n")
    try:
        name = input("Enter user name linked to the code: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not name:
        print("Name must not be empty - cancelled.")
        _pause()
        return
    rc = cmd_issue(_ns(issue=name))
    _pause()
    return rc


def menu_revoke(undo: bool = False) -> None:
    print_banner()
    print(f"--- {'3. Restore access' if undo else '2. Revoke someone'} ---\n")
    reg = load_registry()
    pool = sorted([e for e in reg["codes"] if bool(e.get("revoked")) == undo],
                  key=lambda e: e.get("name", "").lower())
    e = _pick(pool, "revoked" if undo else "active")
    if e is None:
        return
    if not _confirm(f"{'Restore' if undo else 'REVOKE'} {e['name']}?"):
        print("Cancelled.")
        return
    cmd_revoke(_ns(**({"unrevoke": e["name"]} if undo else {"revoke": e["name"]})), undo=undo)
    _pause()


def menu_list() -> None:
    print_banner()
    print("--- 4. List codes ---\n")
    cmd_list(_ns())
    print()
    if _confirm("Reveal plain codes?"):
        print()
        cmd_list(_ns(show_codes=True))
    _pause()


def menu_export() -> None:
    print_banner()
    print("--- 5. Export + publish ---\n")
    rc = cmd_export(_ns())
    if rc == 0:
        print()
        print("Publish checklist:")
        print("  1. Re-obfuscate: node tools/obfuscate-beta.cjs  (from repo root)")
        print("  2. git add murther.user.beta.obfuscated.js beta_auth.json")
        print("  3. git commit + push")
        print("  (Revocation goes live once beta_auth.json is pushed.)")
    _pause()


def menu_verify() -> None:
    print_banner()
    print("--- 6. Verify a code (in BOTH builds) ---\n")
    try:
        code = input("Enter the 6-digit code: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    print()
    check_code_in_files(code)
    _pause()


def menu_bump() -> None:
    print_banner()
    print("--- 7. Version bump ---\n")
    try:
        ver = input("New version (X.Y.Z): ").strip()
        minimum = input("Min allowed version [skip]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not re.fullmatch(r"[0-9][\w.\-]*", ver):
        print("Bad version - cancelled.")
        _pause()
        return
    cmd_bump(_ns(bump_version=ver, min_version=minimum))
    print("Remember: --export, re-obfuscate, commit + push.")
    _pause()


def menu_reissue() -> None:
    print_banner()
    print("--- 8. Re-issue (rotate) a code ---\n")
    reg = load_registry()
    pool = sorted([e for e in reg["codes"] if not e.get("revoked")],
                  key=lambda e: e.get("name", "").lower())
    e = _pick(pool, "active")
    if e is None:
        return
    if not _confirm(f"Rotate {e['name']}'s code? (old code dies, new code issued)"):
        print("Cancelled.")
        return
    salt = reg.get("salt") or new_salt()
    reg["salt"] = salt
    existing = {x.get("code", "") for x in reg["codes"]}
    code = new_code(existing)
    e["revoked"] = True
    e["revoked_at"] = utcnow()
    reg["codes"].append({"name": e["name"], "code": code,
                         "hash": digest(salt, code), "revoked": False,
                         "issued_at": utcnow(), "revoked_at": ""})
    save_registry(reg)
    write_codes_txt(reg)
    print(f"New code for {e['name']} (send privately): {code}")
    print("Next: option 5 (export) -> re-obfuscate -> commit + push")
    _pause()


def menu_delete() -> None:
    print_banner()
    print("--- 9. Delete an entry (permanent) ---\n")
    reg = load_registry()
    pool = sorted(reg["codes"], key=lambda e: e.get("name", "").lower())
    e = _pick(pool, "all")
    if e is None:
        return
    try:
        typed = input(f"Type the name {e['name']!r} to confirm deletion: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if typed.lower() != e["name"].lower():
        print("Name mismatch - cancelled.")
        return
    reg["codes"] = [x for x in reg["codes"] if x is not e]
    save_registry(reg)
    write_codes_txt(reg)
    print(f"Deleted {e['name']} from the registry.")
    print("Next: option 5 (export) -> re-obfuscate -> commit + push")
    _pause()


def menu_status() -> None:
    print_banner()
    print("--- 10. Status ---\n")
    reg = load_registry()
    active = [e for e in reg["codes"] if not e.get("revoked")]
    revoked = [e for e in reg["codes"] if e.get("revoked")]
    print(f"Registry : {len(active)} active, {len(revoked)} revoked")
    print(f"Salt     : {(reg.get('salt') or '')[:12]}... ({len(reg.get('salt') or '')} chars)")
    print(f"Min ver  : {reg.get('min_version', '0.0.1')}")
    try:
        src = JS_FILE.read_text(encoding="utf-8")
        m = re.search(r'var BETA_SALT = "(.*?)";', src)
        n_hash = len(re.findall(r'"[0-9a-f]{64}",', src.split("var BETA_HASHES")[1].split("];")[0])) \
            if "var BETA_HASHES" in src else -1
        print(f"Source .js: salt {'MATCHES' if m and m.group(1) == reg.get('salt') else 'OUT OF SYNC'}"
              f", {n_hash} embedded hash(es) vs {len(active)} active")
    except Exception as ex:
        print(f"Source .js: unreadable ({ex})")
    try:
        auth = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        print(f"beta_auth.json: {auth.get('count_active')} active, "
              f"{len(auth.get('revoked', []))} revoked, updated {auth.get('updated_at', '?')}")
    except Exception as ex:
        print(f"beta_auth.json: unreadable ({ex})")
    _pause()


MENU = [
    ("1", "Create a code", menu_create),
    ("2", "Revoke someone", lambda: menu_revoke(False)),
    ("3", "Restore access (unrevoke)", lambda: menu_revoke(True)),
    ("4", "List codes", menu_list),
    ("5", "Export + publish checklist", menu_export),
    ("6", "Verify a code", menu_verify),
    ("7", "Version bump", menu_bump),
    ("8", "Re-issue (rotate) a code", menu_reissue),
    ("9", "Delete an entry (permanent)", menu_delete),
    ("10", "Status", menu_status),
]


def cmd_menu(args) -> int:
    global USE_COLOR
    if getattr(args, "no_color", False) or not sys.stdin.isatty():
        USE_COLOR = False
    while True:
        if sys.stdin.isatty():
            try:
                os.system("cls" if os.name == "nt" else "clear")
            except Exception:
                pass
        print_banner()
        for key, label, _fn in MENU:
            print(f"  {key:>2}. {label}")
        print("   0. Quit")
        try:
            choice = input("\nType a number: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("0", "q", "quit", "exit"):
            print("Bye.")
            return 0
        hit = next((fn for key, _label, fn in MENU if key == choice), None)
        if hit is None:
            print(f"{choice!r} is not an option - type a number 0-10.")
            _pause()
            continue
        try:
            hit()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        except Exception as ex:
            print(f"Error: {ex}", file=sys.stderr)
            _pause()
    return 0


def _match_pair(text: str, start: int, open_c: str, close_c: str) -> int:
    """Index of the bracket matching text[start] (which must be open_c).

    Skips '...', "...", `...`, //... and /*...*/ so code inside strings or
    comments cannot unbalance the count. Returns -1 on failure.
    """
    i, depth, n = start, 0, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"', "`"):
            quote = c
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _decode_obf_strings(path: Path):
    """Decode a javascript-obfuscator base64 string table by reusing the
    build's OWN decoder + shuffle in Node (pure JS, no DOM touched).

    Returns the decoded string list, or None when the build uses an
    unsupported layout (rc4 keys, split strings, ...) - never raises.
    """
    if shutil.which("node") is None:
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    try:
        # 1. string-table function: function _0xT(){var _0xA=[...]; ... return _0xT();}
        mT = re.search(r"function (_0x\w+)\(\)\{var (_0x\w+)=\[(.*?)\];\1=function\(\)\{return \2;\};return \1\(\);}",
                       text, re.DOTALL)
        if not mT:
            return None
        tname = mT.group(1)
        # 2. decoder: the next 2-arg function containing the base64 alphabet.
        mD = re.search(r"function (_0x\w+)\(_0x\w+,_0x\w+\)\{", text[mT.end():])
        if not mD:
            return None
        dname = mD.group(1)
        dstart = mT.end() + mD.start()
        dbrace = text.find("{", dstart)
        dend = _match_pair(text, dbrace, "{", "}")
        if dend < 0:
            return None
        decoder_src = text[dstart:dend + 1]
        if "decodeURIComponent" not in decoder_src:
            return None  # not the base64 variant (probably rc4) - unsupported
        m_off = re.search(r"-\s*(0x[0-9a-fA-F]+)", decoder_src)
        if not m_off:
            return None
        offset = int(m_off.group(1), 16)
        # 3. shuffle IIFE right after the decoder: (function(a,b){...})(_0xT,0x..)
        rest = text[dend + 1:]
        mS = re.search(r"\(function\(_0x\w+,_0x\w+\)\{", rest)
        send = -1
        if mS:
            sbrace = rest.find("{", mS.start())
            # paren-match from the opening '(' of the IIFE
            send_rel = _match_pair(rest, mS.start(), "(", ")")
            if send_rel > 0 and re.match(r"\(%s,0x[0-9a-fA-F]+\)" % re.escape(tname),
                                         rest[send_rel:send_rel + len(tname) + 24]):
                send = dend + 1 + send_rel + len(re.match(r"\(%s,0x[0-9a-fA-F]+\)" % re.escape(tname),
                                                          rest[send_rel:]).group(0))
        prefix_end = send if send > 0 else dend + 1
        prefix = text[mT.start():prefix_end]
        table_len = len(re.findall(r"'[^']*'", mT.group(3)))
        if table_len < 16:
            return None
        harness = (
            "const vm=require('vm'),fs=require('fs');\n"
            "const machFile=process.argv[2],tName=process.argv[3],"
            "dName=process.argv[4];\n"
            "const off=parseInt(process.argv[5],10),"
            "total=parseInt(process.argv[6],10);\n"
            "const mach=fs.readFileSync(machFile,'utf8');\n"
            "const ctx={};\n"
            "vm.createContext(ctx);\n"
            "vm.runInContext(mach,ctx,{timeout:15000});\n"
            "const out=[];\n"
            "for(let k=0;k<total;k++){\n"
            "  try{const s=vm.runInContext(dName+'('+(off+k)+')',ctx);\n"
            "    out.push(typeof s==='string'?s:null);}catch(e){out.push(null);}\n"
            "}\n"
            "console.log(JSON.stringify({n:total,strings:out}));\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            mach = Path(tmp) / "mach.js"
            drv = Path(tmp) / "drv.js"
            mach.write_text(prefix, encoding="utf-8")
            drv.write_text(harness, encoding="utf-8")
            # NOTE: bytes mode + utf-8/replace on purpose — decoded strings
            # can hold bytes the Windows console codec cannot represent.
            r = subprocess.run(["node", str(drv), str(mach), tname, dname,
                                str(offset), str(table_len)],
                               capture_output=True, timeout=120)
        if r.returncode != 0:
            return None
        out_txt = r.stdout.decode("utf-8", "replace")
        payload = json.loads(out_txt.strip().splitlines()[-1])
        strings = payload.get("strings") or []
        good = [s for s in strings if isinstance(s, str) and s]
        if len(good) < table_len * 0.2:
            return None  # decoded garbage - wrong decoder variant
        return strings
    except Exception:
        return None


def _source_candidates(path: Path):
    """(salt, [hashes], version) parsed from the readable source build."""
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return "", [], ""
    m = re.search(r'var BETA_SALT = "([^"]*)";', src)
    block = re.search(r"var BETA_HASHES = \[(.*?)\];", src, re.DOTALL)
    hashes = re.findall(r'"([0-9a-f]{64})"', block.group(1)) if block else []
    v = re.search(r"// @version\s+([0-9][\w.\-]*)", src)
    return (m.group(1) if m else ""), hashes, (v.group(1) if v else "")


def _prove(code: str, candidates) -> str:
    """Hex salt proving `code`, i.e. sha256(salt + code) is also embedded."""
    hexes = {s for s in candidates if isinstance(s, str) and re.fullmatch(r"[0-9a-f]{64}", s)}
    for s in hexes:
        try:
            if digest(s, code) in hexes:
                return s
        except ValueError:
            return ""
    return ""


def _header_version(path: Path) -> str:
    try:
        head = path.read_text(encoding="utf-8")[:4000]
    except Exception:
        return ""
    m = re.search(r"// @version\s+([0-9][\w.\-]*)", head)
    return m.group(1) if m else ""


def check_code_in_files(code: str):
    """Per-file verdicts for a 6-digit code. Prints a table, returns exit code.

    For each build (source + obfuscated): WORKS / FAIL / UNREADABLE, with the
    reason. WORKS additionally requires the hash to be absent from the live
    revocation list (beta_auth.json), mirroring the gate's runtime check.
    """
    code = (code or "").strip()
    if not re.fullmatch(r"[0-9]{6}", code):
        print("Code must be exactly 6 digits.", file=sys.stderr)
        return 2
    reg = load_registry()
    hit = next((e for e in reg.get("codes", []) if e.get("code") == code), None)
    if hit and not hit.get("revoked"):
        print(f"Registry: {code} belongs to {hit['name']} (active).")
    elif hit:
        print(f"Registry: {code} belongs to {hit['name']}, but it is REVOKED.")
    else:
        print(f"Registry: {code} is unknown (not issued here).")
    try:
        auth = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        revoked_live = {str(x).lower() for x in (auth.get("revoked") or [])}
    except Exception:
        revoked_live = set()
        print("Note: beta_auth.json unreadable - revocation state unknown.")
    # Revocation is decided from registry + live list (mirrors the gate), even
    # when --export already removed the hash from the builds (also blocked).
    try:
        h_reg = digest(reg.get("salt") or "x", code) if reg.get("salt") else ""
    except ValueError:
        h_reg = ""
    is_revoked = bool(h_reg) and (
        h_reg in revoked_live
        or any(e.get("hash") == h_reg and e.get("revoked") for e in reg.get("codes", [])))
    rows = []
    # --- readable source build: exact proof ---
    if JS_FILE.exists():
        salt, hashes, ver = _source_candidates(JS_FILE)
        proof = _prove(code, ([salt] if salt else []) + hashes)
        if proof and not is_revoked:
            rows.append((JS_FILE.name, "WORKS",
                         f"salt {proof[:12]}..., {len(hashes)} hash(es) embedded"))
        elif is_revoked:
            rows.append((JS_FILE.name, "REVOKED",
                         "code is revoked - blocked at runtime"
                         + ("; hash still embedded" if proof else "; hash already removed by --export")))
        elif salt.startswith("CHANGE_ME") or not hashes:
            rows.append((JS_FILE.name, "FAIL",
                         "source has no auth config yet (placeholder salt / empty hashes) - run --export"))
        else:
            rows.append((JS_FILE.name, "FAIL",
                         f"salt {salt[:12]}... carries {len(hashes)} hash(es) but not this code"
                         " - stale source? re-issue/--export, or wrong code"))
    else:
        rows.append((JS_FILE.name, "SKIP", "file not found"))
    # --- obfuscated build: runtime-decoded table + raw literals, then prove ---
    if OBF_FILE.exists():
        ver = _header_version(OBF_FILE)
        try:
            raw = OBF_FILE.read_text(encoding="utf-8")
        except Exception:
            raw = ""
        raw_hex = re.findall(r"[0-9a-f]{64}", raw)
        decoded = _decode_obf_strings(OBF_FILE)  # list, or None if unsupported
        cands = list(decoded or []) + raw_hex
        proof = _prove(code, cands)
        if proof and not is_revoked:
            how = ("decoded table" if decoded and proof in set(decoded) else "embedded literals")
            rows.append((OBF_FILE.name, "WORKS",
                         f"{how} prove it (salt {proof[:12]}...)"))
        elif is_revoked:
            rows.append((OBF_FILE.name, "REVOKED",
                         "code is revoked - blocked at runtime"
                         + ("; hash still embedded" if proof else "; hash already removed by --export")))
        elif decoded is not None or raw_hex:
            rows.append((OBF_FILE.name, "FAIL",
                         "build carries an auth config but not this code - stale build?"
                         " Re-obfuscate after --export, or wrong code."))
        else:
            src_ver = _header_version(JS_FILE)
            hint = (f"versions: build {ver or '?'} vs source {src_ver or '?'}"
                    + (" - MATCH" if ver and ver == src_ver else " - MISMATCH, rebuild first"))
            rows.append((OBF_FILE.name, "UNREADABLE",
                         f"no usable strings found ({hint})."
                         " Re-obfuscate from the exported source, then re-run this check."))
    else:
        rows.append((OBF_FILE.name, "SKIP", "file not found"))
    print()
    for fname, status, detail in rows:
        print(f"{fname}\n  -> {status}: {detail}")
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
    ap.add_argument("--verify", metavar="CODE", default="",
                    help="check a 6-digit code against BOTH builds (source + obfuscated)."
                         " Add --salt + --expect for legacy single-hash mode.")
    ap.add_argument("--expect", default="", help="expected hash for legacy --verify mode")
    ap.add_argument("--menu", action="store_true", help="open the interactive numbered panel")
    ap.add_argument("--no-color", action="store_true", help="plain ASCII banner (no ANSI colors)")
    args = ap.parse_args()

    if len(sys.argv) == 1 or args.menu:
        return cmd_menu(args)

    if args.verify:
        if args.salt or args.expect:
            if not args.salt or not args.expect:
                print("need both --salt and --expect for legacy mode", file=sys.stderr)
                return 2
            got = digest(args.salt, args.verify)
            ok = secrets.compare_digest(got, args.expect.lower())
            print("MATCH" if ok else "NO MATCH")
            print(got)
            return 0 if ok else 1
        return check_code_in_files(args.verify)
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
