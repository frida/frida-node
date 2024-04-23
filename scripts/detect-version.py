import json
from pathlib import Path
import sys


def main():
    root_dir = Path(__file__).parent.parent.resolve()
    pkg_data = json.loads((root_dir / "package.json").read_text(encoding="utf-8"))
    version = pkg_data["version"]
    if version == "0.0.0":
        sys.path.insert(0, str(root_dir))
        from releng.frida_version import detect
        version = detect(root_dir).name
    print(version)


if __name__ == "__main__":
    main()
