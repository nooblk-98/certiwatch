#!/usr/bin/env python3
"""
validate_conf.py — Pre-run validator + auto-fixer for domains.conf and ssl.conf

Checks for:
  1. Malformed entries   (invalid characters, missing TLD, bad port, underscore, etc.)
  2. Duplicates          (case-insensitive, canonical host:port)
  3. DNS reachability    (parallel A/AAAA lookups, optional — skipped with --no-dns)

Auto-fix (always on):
  - Removes malformed entries
  - Removes duplicate entries (keeps first occurrence)
  - Lowercases all entries and normalises the protocol/path
  - Keeps an explicit port when it is not the default 443
  - Strips the www. prefix for domains.conf only: a domain registration is the
    same for www and the bare name, but an SSL endpoint is not, so ssl.conf
    keeps the host exactly as written
  - Rewrites the file in-place with clean entries

Exit codes:
  0  — files clean (or fixed successfully)
  1  — file not found or unrecoverable error

Usage:
  python3 src/validate_conf.py              # fix both files + DNS check
  python3 src/validate_conf.py --no-dns    # fix both files, skip DNS
  python3 src/validate_conf.py ssl.conf    # fix one file only
"""

import argparse
import concurrent.futures
import re
import socket
import sys
import urllib.parse
from pathlib import Path

# ── Colours ────────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def c(colour, text): return f"{colour}{text}{RESET}"

# ── Domain regex ───────────────────────────────────────────────────────────────
LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')

DEFAULT_PORT = 443
DNS_TIMEOUT = 5
DNS_WORKERS = 30


# ── Endpoint parsing ──────────────────────────────────────────────────────────
# Kept in step with src/ssl/scripts/check_ssl.py: a config entry validated here
# is checked exactly as written there.

def parse_endpoint(raw: str) -> tuple[str, int] | None:
    """Parse ``host``, ``host:port`` or a URL into ``(host, port)``."""
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        text = "//" + text

    try:
        parts = urllib.parse.urlsplit(text)
        host = (parts.hostname or "").strip().lower().rstrip(".")
        port = parts.port if parts.port is not None else DEFAULT_PORT
    except ValueError:
        return None

    if not host or "@" in parts.netloc:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def format_endpoint(host: str, port: int) -> str:
    """Canonical target: bare host on 443, otherwise host:port."""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return host if port == DEFAULT_PORT else f"{host}:{port}"


# ── Normalise ──────────────────────────────────────────────────────────────────

def normalise(raw: str, *, strip_www_prefix: bool = True) -> str:
    endpoint = parse_endpoint(raw)
    if endpoint is None:
        # Keep something readable so is_valid() can report the failure.
        return raw.strip().lower()

    host, port = endpoint
    if strip_www_prefix and host.startswith("www."):
        host = host[4:]
    return format_endpoint(host, port)


# ── Validation ─────────────────────────────────────────────────────────────────

def is_valid(domain: str) -> tuple[bool, str]:
    """Return (valid, reason). domain should already be normalised."""
    endpoint = parse_endpoint(domain)
    if endpoint is None:
        return False, f"invalid host or port ('{domain}')"

    host, _port = endpoint
    if not host:
        return False, "empty after normalisation"
    if "_" in host:
        return False, f"contains underscore (malformed: '{host}')"
    labels = host.split(".")
    if len(labels) < 2:
        return False, f"missing TLD ('{host}')"
    for label in labels:
        if not label:
            return False, f"empty label / double dot ('{host}')"
        if not LABEL_RE.match(label):
            return False, f"invalid label '{label}' in '{host}'"
    if len(labels[-1]) < 2:
        return False, f"TLD too short in '{host}'"
    return True, ""


# ── DNS check ─────────────────────────────────────────────────────────────────

def dns_check(domain: str) -> tuple[str, bool, str]:
    endpoint = parse_endpoint(domain)
    host = endpoint[0] if endpoint else domain
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        socket.getaddrinfo(host, None)
        return domain, True, ""
    except socket.gaierror as e:
        return domain, False, str(e)
    except Exception as e:
        return domain, False, str(e)


# ── Process one file ───────────────────────────────────────────────────────────

def process_file(path: Path, check_dns: bool, strip_www_prefix: bool = True) -> bool:
    """
    Validate, auto-fix, and rewrite path in-place.
    Returns True if file is clean after fixing.
    """
    print(f"\n{c(CYAN, f'Processing {path}…')}")

    if not path.exists():
        print(f"  {c(RED, 'ERROR:')} File not found: {path}")
        return False

    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    removed_malformed: list[tuple[int, str, str]] = []  # (lineno, raw, reason)
    removed_duplicates: list[tuple[int, str]] = []      # (lineno, norm)
    kept: list[str] = []                                 # normalised, clean, unique
    seen: dict[str, int] = {}                            # norm → original lineno

    for lineno, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        raw = stripped.split()[0]
        norm = normalise(raw, strip_www_prefix=strip_www_prefix)

        valid, reason = is_valid(norm)
        if not valid:
            removed_malformed.append((lineno, raw, reason))
            continue

        if norm in seen:
            removed_duplicates.append((lineno, norm))
        else:
            seen[norm] = lineno
            kept.append(norm)

    # DNS check on kept domains (host part only)
    dns_unreachable: list[tuple[str, str]] = []
    if check_dns and kept:
        print(f"  {c(DIM, f'Checking DNS for {len(kept)} domains…')}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
            futures = {pool.submit(dns_check, d): d for d in kept}
            for fut in concurrent.futures.as_completed(futures):
                domain, ok, err = fut.result()
                if not ok:
                    dns_unreachable.append((domain, err))
        dns_unreachable.sort()

    # ── Print summary ──────────────────────────────────────────────────────────
    total_removed = len(removed_malformed) + len(removed_duplicates)

    if removed_malformed:
        print(f"\n  {c(RED + BOLD, f'Removed malformed ({len(removed_malformed)}):')}")
        for lineno, raw, reason in removed_malformed:
            print(f"    Line {lineno:4d}: {c(RED, raw):<40}  {reason}")

    if removed_duplicates:
        print(f"\n  {c(YELLOW + BOLD, f'Removed duplicates ({len(removed_duplicates)}):')}")
        for lineno, norm in removed_duplicates:
            print(f"    Line {lineno:4d}: {c(YELLOW, norm)}")

    if dns_unreachable:
        print(f"\n  {c(YELLOW + BOLD, f'DNS unreachable ({len(dns_unreachable)}) — kept in file:')}")
        for domain, err in dns_unreachable:
            print(f"    {c(YELLOW, domain):<45}  {err}")

    # ── Rewrite file ───────────────────────────────────────────────────────────
    if total_removed > 0:
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        print(f"\n  {c(GREEN, '✓')} Rewrote {path.name}: "
              f"{len(raw_lines)} lines → {len(kept)} clean entries "
              f"({total_removed} removed)")
    else:
        print(f"\n  {c(GREEN, '✓')} {path.name} is already clean "
              f"({len(kept)} entries, nothing removed)")

    return True


# ── Entry point ────────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FILES = [str(ROOT_DIR / "ssl.conf"), str(ROOT_DIR / "domains.conf")]
DEFAULT_TOML = ROOT_DIR / "certiwatch.toml"


def strip_www_for(path: Path) -> bool:
    """A TLS endpoint keeps www; a domain registration does not need it."""
    return path.name != "ssl.conf"


def _validate_toml(path: Path) -> bool:
    from config import ConfigError, load_config

    try:
        loaded = load_config(path)
    except (ConfigError, OSError) as exc:
        print(f"\n  {c(RED, 'ERROR:')} {exc}")
        return False

    print(
        f"\n  {c(GREEN, '✓')} {path.name} is valid "
        f"({len(loaded.targets)} targets, thresholds "
        f"{list(loaded.thresholds)}, history_limit={loaded.history_limit})"
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate certiwatch.toml, and optionally clean legacy .conf files."
    )
    parser.add_argument(
        "files",
        nargs="*",
        default=[],
        help="Legacy config files to process (default: ssl.conf domains.conf)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help=f"TOML file to validate (default: {DEFAULT_TOML.name} when present)",
    )
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Also validate and auto-fix the legacy ssl.conf/domains.conf files",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS reachability checks (faster)",
    )
    args = parser.parse_args()

    check_dns = not args.no_dns
    toml_path = Path(args.config) if args.config else (
        DEFAULT_TOML if DEFAULT_TOML.exists() else None
    )

    print(c(BOLD, "\n=== CertiWatch config validator + auto-fixer ==="))
    print(f"  {c(DIM, 'DNS checks ' + ('disabled' if not check_dns else 'enabled (--no-dns to skip)'))}")

    if toml_path is not None:
        if not _validate_toml(toml_path):
            print(f"\n{'─' * 55}")
            print(c(RED + BOLD, "  Configuration is invalid.\n"))
            return 1
        if not args.files and not args.legacy:
            print(f"\n{'─' * 55}")
            print(c(GREEN + BOLD, "  Done. TOML configuration is clean.\n"))
            return 0

    paths = [Path(f) for f in (args.files or DEFAULT_FILES)]
    ok = all([process_file(p, check_dns, strip_www_for(p)) for p in paths])

    print(f"\n{'─' * 55}")
    if ok:
        print(c(GREEN + BOLD, "  Done. Config files are clean.\n"))
        return 0
    else:
        print(c(RED + BOLD, "  One or more files could not be processed.\n"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
