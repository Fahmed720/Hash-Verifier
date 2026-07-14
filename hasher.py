#!/usr/bin/env python3
"""
File Hash Verifier - Cybersecurity Portfolio Project
Author: [Your Name]
Description: Computes and verifies cryptographic hashes (MD5, SHA1, SHA256,
             SHA512) for files. Useful for integrity checking, download
             verification, and basic digital forensics.
"""

import hashlib
import os
import sys
import argparse
import json
from datetime import datetime
from pathlib import Path


# ─── Supported algorithms ─────────────────────────────────────────────────────

ALGORITHMS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

# MD5 and SHA1 are included for compatibility (e.g. checking old download pages)
# but flagged as weak when used for security purposes
WEAK_ALGORITHMS = {"md5", "sha1"}

CHUNK_SIZE = 65536  # 64 KB — read large files in chunks to avoid loading into RAM


# ─── Core hashing ─────────────────────────────────────────────────────────────

def hash_file(filepath: str, algorithm: str) -> str:
    """
    Compute the hash of a file using the specified algorithm.
    Reads the file in chunks so large files do not exhaust memory.
    Returns the hex digest string.
    """
    h = ALGORITHMS[algorithm]()
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {filepath}")

    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)

    return h.hexdigest()


def hash_file_all(filepath: str) -> dict:
    """Compute all supported hash algorithms for a single file."""
    results = {}
    for alg in ALGORITHMS:
        results[alg] = hash_file(filepath, alg)
    return results


def verify_hash(filepath: str, algorithm: str, expected: str) -> bool:
    """
    Compare the computed hash of a file against an expected value.
    Comparison is case-insensitive.
    """
    computed = hash_file(filepath, algorithm)
    return computed.lower() == expected.lower().strip()


# ─── Hash manifest (batch operations) ────────────────────────────────────────

def build_manifest(directory: str, algorithm: str, recursive: bool) -> dict:
    """
    Walk a directory and compute hashes for every file found.
    Returns a dict mapping relative file paths to their hash values.
    """
    manifest = {}
    base = Path(directory)

    pattern = "**/*" if recursive else "*"
    files = [p for p in base.glob(pattern) if p.is_file()]

    print(f"\n[*] Building manifest for {len(files)} file(s) in '{directory}'...\n")

    for i, filepath in enumerate(sorted(files), 1):
        rel_path = str(filepath.relative_to(base))
        try:
            manifest[rel_path] = hash_file(str(filepath), algorithm)
            print(f"  [{i:>4}/{len(files)}]  {rel_path}")
        except Exception as e:
            manifest[rel_path] = f"ERROR: {e}"
            print(f"  [{i:>4}/{len(files)}]  {rel_path}  [ERROR: {e}]")

    return manifest


def save_manifest(manifest: dict, algorithm: str, directory: str, output_path: str):
    """Save a manifest to a JSON file for later verification."""
    data = {
        "created":   datetime.now().isoformat(),
        "directory": str(Path(directory).resolve()),
        "algorithm": algorithm,
        "files":     manifest,
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[*] Manifest saved to: {output_path}")


def verify_manifest(manifest_path: str) -> list:
    """
    Load a previously saved manifest and re-hash every file to detect changes.
    Returns a list of result dicts describing each file's status.
    """
    with open(manifest_path, "r") as f:
        data = json.load(f)

    base      = Path(data["directory"])
    algorithm = data["algorithm"]
    files     = data["files"]
    results   = []

    print(f"\n[*] Verifying {len(files)} file(s) against manifest...")
    print(f"    Algorithm : {algorithm.upper()}")
    print(f"    Base path : {base}\n")

    for rel_path, expected_hash in files.items():
        filepath = base / rel_path
        entry = {"path": rel_path, "status": "", "expected": expected_hash, "computed": ""}

        if not filepath.exists():
            entry["status"] = "MISSING"
            entry["computed"] = "—"
        elif expected_hash.startswith("ERROR:"):
            entry["status"] = "SKIP"
            entry["computed"] = "—"
        else:
            try:
                computed = hash_file(str(filepath), algorithm)
                entry["computed"] = computed
                entry["status"] = "OK" if computed.lower() == expected_hash.lower() else "CHANGED"
            except Exception as e:
                entry["status"] = "ERROR"
                entry["computed"] = str(e)

        icon = {"OK": "✓", "CHANGED": "✗", "MISSING": "?", "ERROR": "!", "SKIP": "-"}.get(entry["status"], " ")
        print(f"  [{icon}] {rel_path}  ({entry['status']})")
        results.append(entry)

    return results


# ─── Report generation ────────────────────────────────────────────────────────

def save_report(results: dict, output_path: str):
    """Save a plain-text verification report."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  FILE HASH VERIFIER — REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        if results.get("type") == "single":
            f.write(f"  File    : {results['filepath']}\n")
            f.write(f"  Size    : {results['size']}\n\n")
            f.write(f"  {'Algorithm':<10}  Hash\n")
            f.write("  " + "-" * 60 + "\n")
            for alg, digest in results["hashes"].items():
                weak = "  ⚠ weak" if alg in WEAK_ALGORITHMS else ""
                f.write(f"  {alg.upper():<10}  {digest}{weak}\n")

        elif results.get("type") == "verify":
            f.write(f"  Manifest: {results['manifest']}\n\n")
            ok = changed = missing = 0
            for r in results["file_results"]:
                if r["status"] == "OK":      ok += 1
                if r["status"] == "CHANGED": changed += 1
                if r["status"] == "MISSING": missing += 1
            f.write(f"  Result  : {ok} OK  |  {changed} CHANGED  |  {missing} MISSING\n\n")
            f.write(f"  {'STATUS':<10}  {'FILE'}\n")
            f.write("  " + "-" * 60 + "\n")
            for r in results["file_results"]:
                f.write(f"  {r['status']:<10}  {r['path']}\n")
                if r["status"] == "CHANGED":
                    f.write(f"    Expected: {r['expected']}\n")
                    f.write(f"    Computed: {r['computed']}\n")

        f.write("\n" + "=" * 70 + "\n")

    print(f"[*] Report saved to: {output_path}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="File Hash Verifier — Integrity checking and forensics tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Hash a single file (all algorithms):
    python hasher.py hash suspicious_file.exe

  Hash with a specific algorithm:
    python hasher.py hash download.zip --alg sha256

  Verify a file against a known hash:
    python hasher.py verify installer.exe --alg sha256 --expected abc123...

  Build a manifest of a folder:
    python hasher.py manifest ./project --alg sha256 --save manifest.json

  Check a folder against a saved manifest:
    python hasher.py check manifest.json
        """
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # hash command
    p_hash = sub.add_parser("hash", help="Compute hash(es) for a file")
    p_hash.add_argument("file", help="Path to the file")
    p_hash.add_argument("--alg", choices=ALGORITHMS.keys(), default=None,
                        help="Algorithm (default: all)")
    p_hash.add_argument("--report", metavar="PATH", help="Save report to file")

    # verify command
    p_verify = sub.add_parser("verify", help="Check a file against a known hash")
    p_verify.add_argument("file", help="Path to the file")
    p_verify.add_argument("--alg", choices=ALGORITHMS.keys(), required=True)
    p_verify.add_argument("--expected", required=True, help="Expected hash value")

    # manifest command
    p_manifest = sub.add_parser("manifest", help="Hash all files in a directory")
    p_manifest.add_argument("directory", help="Directory to scan")
    p_manifest.add_argument("--alg", choices=ALGORITHMS.keys(), default="sha256")
    p_manifest.add_argument("--save", metavar="PATH", required=True,
                            help="Where to save the manifest JSON")
    p_manifest.add_argument("-r", "--recursive", action="store_true",
                            help="Include subdirectories")

    # check command
    p_check = sub.add_parser("check", help="Verify directory against a saved manifest")
    p_check.add_argument("manifest", help="Path to manifest JSON file")
    p_check.add_argument("--report", metavar="PATH", help="Save report to file")

    return parser.parse_args()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    print("\n" + "=" * 70)
    print("  FILE HASH VERIFIER")
    print("=" * 70)

    # ── hash ──────────────────────────────────────────────────────────────────
    if args.command == "hash":
        filepath = args.file
        size = os.path.getsize(filepath)
        size_str = f"{size:,} bytes"

        print(f"\n  File : {filepath}")
        print(f"  Size : {size_str}\n")

        if args.alg:
            algorithms = [args.alg]
        else:
            algorithms = list(ALGORITHMS.keys())

        hashes = {}
        for alg in algorithms:
            digest = hash_file(filepath, alg)
            hashes[alg] = digest
            weak = "  ⚠  weak algorithm — do not use for security purposes" if alg in WEAK_ALGORITHMS else ""
            print(f"  {alg.upper():<10}  {digest}{weak}")

        if args.report:
            save_report({
                "type": "single",
                "filepath": filepath,
                "size": size_str,
                "hashes": hashes,
            }, args.report)

    # ── verify ────────────────────────────────────────────────────────────────
    elif args.command == "verify":
        print(f"\n  File      : {args.file}")
        print(f"  Algorithm : {args.alg.upper()}")
        print(f"  Expected  : {args.expected}\n")

        computed = hash_file(args.file, args.alg)
        print(f"  Computed  : {computed}\n")

        if verify_hash(args.file, args.alg, args.expected):
            print("  [✓] MATCH — file integrity confirmed.")
        else:
            print("  [✗] MISMATCH — file may be corrupted or tampered with.")
            sys.exit(1)

    # ── manifest ──────────────────────────────────────────────────────────────
    elif args.command == "manifest":
        manifest = build_manifest(args.directory, args.alg, args.recursive)
        save_manifest(manifest, args.alg, args.directory, args.save)
        print(f"\n[*] {len(manifest)} file(s) hashed with {args.alg.upper()}.")

    # ── check ─────────────────────────────────────────────────────────────────
    elif args.command == "check":
        file_results = verify_manifest(args.manifest)

        ok      = sum(1 for r in file_results if r["status"] == "OK")
        changed = sum(1 for r in file_results if r["status"] == "CHANGED")
        missing = sum(1 for r in file_results if r["status"] == "MISSING")

        print(f"\n[*] Summary: {ok} OK  |  {changed} CHANGED  |  {missing} MISSING")

        if changed or missing:
            print("[!] Integrity issues detected.")

        if args.report:
            save_report({
                "type": "verify",
                "manifest": args.manifest,
                "file_results": file_results,
            }, args.report)

        if changed or missing:
            sys.exit(1)


if __name__ == "__main__":
    main()
