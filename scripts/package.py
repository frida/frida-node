from pathlib import Path
import sys
import tarfile


def main(argv: list[str]):
    binding = Path(argv[1])
    outfile = Path(argv[2])

    with tarfile.open(outfile, "w:gz") as tar:
        tar.add(binding, arcname="build/frida_binding.node")


if __name__ == "__main__":
    main(sys.argv)
