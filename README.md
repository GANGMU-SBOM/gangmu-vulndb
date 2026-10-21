# gangmu-vulndb

A public, unofficial snapshot of the [NVD](https://nvd.nist.gov/) CVE feed, packaged for
[gangmu](https://github.com/GANGMU-SBOM/gangmu). It exists so you do not have to start
`gangmu vuln-fetch --all` from zero (hours, rate-limited, easy to interrupt). Unpack it,
then let gangmu fetch only what changed since.

The data is not in git. Each snapshot is a [Release](../../releases) asset.
This repository holds the build script and these instructions.

## Use

```sh
base=https://github.com/GANGMU-SBOM/gangmu-vulndb/releases/latest/download
curl -LO $base/nvd-snapshot.tar && curl -LO $base/SHA256SUMS
sha256sum -c SHA256SUMS

mkdir -p ~/.cache/gangmu-vuln
tar -xf nvd-snapshot.tar -C ~/.cache/gangmu-vuln

# bring it up to date (incremental from the snapshot date; skip when offline)
gangmu vuln-fetch --db ~/.cache/gangmu-vuln --all          # add --api-key KEY for ~10x speed

gangmu vuln --sbom sbom.json --db ~/.cache/gangmu-vuln
```

For an air-gapped network: do the steps up to `vuln-fetch` on a connected machine and
copy the directory in. `gangmu vuln` only reads the local directory.

If you only need one firmware's products, `gangmu vuln-fetch --db DIR --sbom sbom.json`
is faster than any snapshot.

Do not unpack over a directory you already filled: the snapshot's state file would
move your watermark back. Use a fresh directory.

## What is in a release

| File | |
|---|---|
| `nvd-snapshot.tar` | `nvd-<year>.json.xz` shards and a `.gangmu-fetch.state` holding only `nvd_watermark` |
| `SHA256SUMS` | checksum of the tar |
| `MANIFEST.json` | snapshot date, watermark, record count, the gangmu version that built it |

`MANIFEST.json.schema` is `gangmu-vulndb/1`. A snapshot is only as new as its watermark;
records modified after it are what the incremental `vuln-fetch` brings in.

## Build one

```sh
python3 scripts/build_snapshot.py --workdir /data/nvd-work --out /data/out --api-key KEY
```

Runs `gangmu vuln-fetch --all` (resumable: rerun the same command if it breaks), refuses to
package an unfinished download, then writes the three files above. Attach them to a Release
named by date, e.g. `snapshot-2026-10`.

## Source and license

Records come unmodified from the NVD API (U.S. government work, public domain). This is not
an NVD product and is not endorsed by NIST. Scripts: Apache-2.0.
