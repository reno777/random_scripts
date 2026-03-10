#!/usr/bin/env python3
"""
spycloud_match.py - Match SpyCloud breach dump users against a verified internal user list.
Author: reno777
"""

import csv
import sys
import argparse

BANNER = r"""
 ____               ____ _                 _
/ ___| _ __  _   _ / ___| | ___  _   _  __| |
\___ \| '_ \| | | | |   | |/ _ \| | | |/ _` |
 ___) | |_) | |_| | |___| | (_) | |_| | (_| |
|____/| .__/ \__, |\____|_|\___/ \__,_|\__,_|
      |_|    |___/
 __  __       _       _
|  \/  | __ _| |_ ___| |__
| |\/| |/ _` | __/ __| '_ \
| |  | | (_| | || (__| | | |
|_|  |_|\__,_|\__\___|_| |_|
  Match SpyCloud dumps against internal users
  Author: reno777
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="spycloud_match.py",
        description="Match usernames from a SpyCloud CSV dump against a verified internal user list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s internal_users.txt spycloud_dump.csv
  %(prog)s internal_users.txt spycloud_dump.csv -o matches.txt
  %(prog)s internal_users.txt spycloud_dump.csv -q

notes:
  FILE1 (internal users) expects one username per line
  FILE2 (SpyCloud CSV) is the raw SpyCloud export with a header row.
    Required columns: username, password_plaintext (or password as fallback)
  Matched records are printed as username,password to stdout.
        """,
    )
    parser.add_argument("users_file", metavar="FILE1", help="Internal verified users list (one per line)")
    parser.add_argument("dump_file", metavar="FILE2", help="SpyCloud CSV export (with header row)")
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write matches to a file instead of stdout",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress the banner and informational messages",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.quiet:
        print(BANNER)

    # Load internal usernames into a set for fast lookups
    try:
        with open(args.users_file, "r") as f:
            target_users = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"[!] Error: users file not found: {args.users_file}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"[*] Loaded {len(target_users)} internal users from '{args.users_file}'")

    # Scan the SpyCloud CSV export for matching usernames
    matches = []
    try:
        with open(args.dump_file, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            if "username" not in (reader.fieldnames or []):
                print("[!] Error: SpyCloud CSV is missing a 'username' column.", file=sys.stderr)
                sys.exit(1)
            for row in reader:
                username = (row.get("username") or "").strip()
                if not username or username not in target_users:
                    continue
                # Prefer plaintext password; fall back to hashed password field
                password = (row.get("password_plaintext") or row.get("password") or "").strip()
                matches.append(f"{username},{password}")
    except FileNotFoundError:
        print(f"[!] Error: dump file not found: {args.dump_file}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"[*] Found {len(matches)} match(es)\n")

    if not matches:
        if not args.quiet:
            print("[-] No matching users found.")
        sys.exit(0)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(matches) + "\n")
        if not args.quiet:
            print(f"[+] Results written to '{args.output}'")
    else:
        for match in matches:
            print(match)


if __name__ == "__main__":
    main()
