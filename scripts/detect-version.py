#!/usr/bin/env python3

import json
from pathlib import Path
import sys


def main(argv):
    pkg_file = Path(argv[1])
    pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    print(pkg_data["version"])


if __name__ == "__main__":
    main(sys.argv)
