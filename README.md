# File Hash Verifier

A command-line tool for computing and verifying cryptographic file hashes. Supports MD5, SHA1, SHA256, and SHA512. Useful for checking download integrity, detecting file tampering, and building basic forensic workflows.

Built as part of a cybersecurity portfolio to demonstrate knowledge of cryptographic hashing, file integrity checking, and the role of checksums in security.

---

## Features

- Hash any file using MD5, SHA1, SHA256, or SHA512 (or all at once)
- Verify a file against a known hash — outputs a clear MATCH / MISMATCH result
- Build a **hash manifest** of an entire directory for baseline integrity monitoring
- **Check a directory** against a saved manifest to detect added, changed, or missing files
- Flags MD5 and SHA1 as weak algorithms when used in a security context
- Reads files in chunks — works correctly on large files without memory issues
- Optional plain-text report output

---

## Requirements

- Python 3.8 or higher
- No external packages required (uses stdlib only: `hashlib`, `pathlib`, `json`, `argparse`)

---

## Usage

### Hash a file

```bash
# All algorithms at once
python hasher.py hash myfile.zip

# Specific algorithm
python hasher.py hash myfile.zip --alg sha256

# Save a report
python hasher.py hash myfile.zip --report reports/hash_report.txt
```

### Verify a file against a known hash

```bash
python hasher.py verify ubuntu-24.04.iso --alg sha256 --expected <paste hash here>
```

### Build a manifest of a directory

```bash
# Hash every file in a folder
python hasher.py manifest ./project --alg sha256 --save manifest.json

# Include subdirectories
python hasher.py manifest ./project --alg sha256 --save manifest.json -r
```

### Check a directory against a saved manifest

```bash
python hasher.py check manifest.json

# Save a report of changes
python hasher.py check manifest.json --report reports/integrity_report.txt
```

---

## Sample output

```
======================================================================
  FILE HASH VERIFIER
======================================================================

  File : ubuntu-24.04.iso
  Size : 2,097,152,000 bytes

  MD5         5d41402abc4b2a76b9719d911017c592  ⚠  weak algorithm
  SHA1        da39a3ee5e6b4b0d3255bfef95601890afd80709  ⚠  weak algorithm
  SHA256      3b4c6d8e1f9a2b7c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7
  SHA512      9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08...
```

```
  [✓] MATCH — file integrity confirmed.
```

```
  [✓] ubuntu.iso      (OK)
  [✗] config.cfg      (CHANGED)
  [?] notes.txt       (MISSING)

  Summary: 1 OK  |  1 CHANGED  |  1 MISSING
  [!] Integrity issues detected.
```

---

## How it works

1. **Chunked reading** — files are read in 64 KB blocks and fed into the hash function incrementally, so even a 50 GB file is handled without loading it all into memory
2. **hashlib** — Python's built-in cryptographic library wraps proven C implementations of each algorithm
3. **Manifest mode** — snapshots the hash of every file in a directory to a JSON file; running `check` later re-hashes everything and compares, flagging any differences
4. **Algorithm warnings** — MD5 and SHA1 are collision-vulnerable; the tool flags their use so the output is honest about what they can and cannot prove

---

## What I learned

- How cryptographic hash functions work (deterministic, one-way, collision-resistant)
- Why MD5 and SHA1 are considered broken for security use (collision attacks)
- Why SHA256 is the current standard for file integrity verification
- How chunked file reading prevents memory exhaustion on large files
- How hash manifests are used in file integrity monitoring tools like Tripwire and AIDE
- The difference between hashing (integrity) and encryption (confidentiality)

---

## Real-world applications

| Use case | How this tool helps |
|---|---|
| Verifying a downloaded ISO | `verify` command checks it matches the publisher's posted hash |
| Detecting malware modification | `manifest` + `check` reveals any file that changed after a known-good baseline |
| Digital forensics | Hash evidence files to prove they were not altered after collection |
| Software supply chain | Hash build artefacts to detect tampering before deployment |

---

## Limitations and possible extensions

- Does not handle symbolic links (skipped silently)
- Manifest paths are absolute — moving the directory breaks verification
- Could be extended to watch a directory in real-time using `watchdog`
- Could output JSON for integration with SIEM tools
- Could add HMAC support for authenticated integrity checks

---

## Project structure

```
hash-verifier/
├── hasher.py       — main script
├── README.md       — this file
└── reports/        — auto-created; stores report output files
```
