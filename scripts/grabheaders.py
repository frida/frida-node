from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import urllib.request


def main(node: Path, outdir: Path):
    target = outdir / "abi-headers"
    if target.exists():
        return

    version = subprocess.run([node, "--version"], capture_output=True, encoding="utf-8").stdout.strip()

    url = f"https://nodejs.org/dist/{version}/node-{version}-headers.tar.xz"

    with urllib.request.urlopen(url) as response:
        tar_blob = response.read()

    with tarfile.open(fileobj=BytesIO(tar_blob), mode="r:xz") as tar:
        tar.extractall(outdir)

    os.rename(outdir / f"node-{version}", target)


if __name__ == "__main__":
    node = Path(sys.argv[1])
    outdir = Path(sys.argv[2])
    main(node, outdir)
