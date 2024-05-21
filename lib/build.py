from pathlib import Path
import shutil
import subprocess
import sys


def main(argv: list[str]):
    outdir, privdir, npm, package_json, tsconfig, *sources = [Path(s) for s in argv[1:]]

    try:
        privdir.mkdir(exist_ok=True)
        for asset in [package_json, tsconfig]:
            shutil.copy(asset, privdir)

        libdir = privdir / "lib"
        if libdir.exists():
            shutil.rmtree(libdir)
        libdir.mkdir()
        for asset in sources:
            shutil.copy(asset, libdir)

        distdir = privdir / "dist"
        if distdir.exists():
            shutil.rmtree(distdir)

        run_kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "encoding": "utf-8",
            "check": True,
        }
        subprocess.run([npm, "install", "--ignore-scripts"],
                       cwd=privdir,
                       **run_kwargs)
        subprocess.run([npm, "run", "build"],
                       cwd=privdir,
                       **run_kwargs)

        for asset in sources:
            for ext in [".js", ".d.ts"]:
                shutil.copy(distdir / (asset.stem + ext), outdir)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        print("Output:\n\t| " + "\n\t| ".join(e.output.strip().split("\n")), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
