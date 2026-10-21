#!/usr/bin/env python3
"""Build an NVD snapshot for ``gangmu vuln`` from a fresh ``gangmu vuln-fetch --all``.

Output (in --out): nvd-snapshot-<YYYYMMDD>.tar, SHA256SUMS, MANIFEST.json.

The tar holds only what a user needs to continue incrementally: the nvd-<year>.json.xz
shards and a .gangmu-fetch.state reduced to ``nvd_watermark``. Machine-local state
(``nvd_page``) and anything else in the directory (analysis cache, threat/, osv/) is left out.
The shards are already xz, so the tar is not compressed again.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = ".gangmu-fetch.state"      # same name as gangmu.vuln.fetch.STATE_FILE
SCHEMA = "gangmu-vulndb/1"


def fail(msg: str) -> "None":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def check_complete(work: Path) -> dict:
    """The directory must be a finished full download, or the snapshot would be a lie."""
    junk = [p.name for p in work.iterdir() if p.name.endswith((".tmp", ".unreadable"))]
    if junk:
        fail(f"leftover files, not a clean download: {junk}")
    try:
        state = json.loads((work / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"cannot read {STATE_FILE}: {exc}")
    if "nvd_full" in state:
        fail("the full download is unfinished (state has nvd_full); run vuln-fetch again")
    if not state.get("nvd_watermark"):
        fail("state has no nvd_watermark")
    return state


def count_records(shards: list[Path]) -> int:
    total = 0
    for path in shards:
        with lzma.open(path, "rt", encoding="utf-8") as fh:
            total += len(json.load(fh).get("vulnerabilities", []))
    return total


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workdir", type=Path, required=True,
                    help="fetch here; must be empty or hold an earlier run of this script")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--api-key", help="NVD API key (or set NVD_API_KEY)")
    ap.add_argument("--skip-fetch", action="store_true",
                    help="package --workdir as it is (it must be a finished full download)")
    args = ap.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)
    if not args.skip_fetch:
        cmd = ["gangmu", "vuln-fetch", "--db", str(args.workdir), "--all", "-v"]
        if args.api_key:
            cmd += ["--api-key", args.api_key]
        if subprocess.run(cmd).returncode:
            fail("vuln-fetch failed; run the script again to resume")

    state = check_complete(args.workdir)
    shards = sorted(args.workdir.glob("nvd-*.json.xz"))
    if not shards:
        fail("no nvd-*.json.xz shards")
    records = count_records(shards)

    try:
        version = subprocess.run(["gangmu", "--version"], capture_output=True, text=True)
        gangmu_version = (version.stdout or version.stderr).strip() or "unknown"
    except OSError:
        gangmu_version = "unknown"

    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    args.out.mkdir(parents=True, exist_ok=True)
    tar_path = args.out / f"nvd-snapshot-{day}.tar"
    state_copy = args.out / STATE_FILE
    state_copy.write_text(json.dumps({"nvd_watermark": state["nvd_watermark"]}, indent=1),
                          encoding="utf-8")
    with tarfile.open(tar_path, "w") as tar:
        for path in shards + [state_copy]:
            info = tar.gettarinfo(str(path), arcname=path.name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as fh:
                tar.addfile(info, fh)
    state_copy.unlink()

    digest = sha256(tar_path)
    (args.out / "SHA256SUMS").write_text(f"{digest}  {tar_path.name}\n", encoding="utf-8")
    manifest = {
        "schema": SCHEMA,
        "snapshot": day,
        "file": tar_path.name,
        "sha256": digest,
        "size": tar_path.stat().st_size,
        "nvd_watermark": state["nvd_watermark"],
        "records": records,
        "shards": [p.name for p in shards],
        "built_with": gangmu_version,
    }
    (args.out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n",
                                            encoding="utf-8")
    print(f"{tar_path.name}: {records} records, {manifest['size'] >> 20} MiB, "
          f"watermark {state['nvd_watermark']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
