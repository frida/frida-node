#!/usr/bin/env python3

import json
from pathlib import Path
import sys


def main(argv):
    pkg_file = Path(argv[1])
    pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    version = pkg_data["version"]
    if version == "0.0.0":
        root_dir = Path(__file__).parent.parent.resolve()
        sys.path.insert(0, str(root_dir))
        from releng.frida_version import detect
        version = detect(root_dir).name
    print(version)


if __name__ == "__main__":
    main(sys.argv)
