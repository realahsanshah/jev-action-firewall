"""Install jev-firewall into a fresh venv per consumer example and run it, like a user would.

    python scripts/verify_consumer_examples.py --source local                 # before publishing: dist/*.whl
    python scripts/verify_consumer_examples.py --source local --installer uv  # same, installing with uv
    python scripts/verify_consumer_examples.py --source testpypi              # after a TestPyPI upload
    python scripts/verify_consumer_examples.py --source pypi                  # after the real release

Each example in examples/consumer/<extra>/ has a requirements.txt pinning
`jev-firewall[<extra>]==<version>`, a policy.yaml, and an app.py that imports nothing from
this repo. Needs `uv` (to create the venvs). TYPESAFE_API_KEY is removed from the child
environment unless --live is given, so the default run is offline and free.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "consumer"

TESTPYPI = ["--index-url", "https://test.pypi.org/simple/", "--extra-index-url", "https://pypi.org/simple/"]
IndexArgs = Callable[[Path], list[str]]
INDEX_ARGS: dict[str, dict[str, IndexArgs]] = {
    "pip": {
        "local": lambda dist: ["--find-links", str(dist), "--no-cache-dir"],
        "testpypi": lambda dist: [*TESTPYPI, "--no-cache-dir"],
        "pypi": lambda dist: ["--no-cache-dir"],
    },
    "uv": {
        "local": lambda dist: ["--find-links", str(dist), "--refresh-package", "jev-firewall"],
        "testpypi": lambda dist: [*TESTPYPI, "--index-strategy", "unsafe-best-match", "--refresh"],
        "pypi": lambda dist: ["--refresh-package", "jev-firewall"],
    },
}


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def verify(
    example: Path, source: str, installer: str, python: str, live: bool, dist: Path
) -> tuple[bool, str]:
    env = dict(os.environ)
    if not live:
        env.pop("TYPESAFE_API_KEY", None)
    with tempfile.TemporaryDirectory(prefix=f"jevfw-{example.name}-") as tmp:
        work = Path(tmp) / example.name
        shutil.copytree(example, work)
        venv = work / ".venv"
        py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        index = INDEX_ARGS[installer][source](dist)
        if installer == "pip":
            install = [str(py), "-m", "pip", "install", "--quiet", "-r", "requirements.txt", *index]
        else:
            install = [
                "uv",
                "pip",
                "install",
                "--quiet",
                "--python",
                str(venv),
                "-r",
                "requirements.txt",
                *index,
            ]
        for cmd in (["uv", "venv", "--quiet", "--seed", "--python", python, str(venv)], install):
            r = run(cmd, work, env)
            if r.returncode != 0:
                return False, f"$ {' '.join(cmd)}\n{r.stdout}{r.stderr}"
        r = run([str(py), "app.py"], work, env)
        ok = r.returncode == 0 and "blocked" in r.stdout.lower()
        return ok, r.stdout + r.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=["local", "testpypi", "pypi"], default="local")
    ap.add_argument("--installer", choices=["pip", "uv"], default="pip", help="how the user installs")
    ap.add_argument("--python", default="3.11", help="interpreter version for the fresh venvs")
    ap.add_argument("--only", nargs="*", help="subset of examples, e.g. langgraph google_adk")
    ap.add_argument("--live", action="store_true", help="pass TYPESAFE_API_KEY through to the examples")
    ap.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = ap.parse_args()

    if args.source == "local" and not list(args.dist.glob("jev_firewall-*.whl")):
        print(f"no wheel in {args.dist}; run `uv build` first")
        return 2

    names = args.only or sorted(p.name for p in EXAMPLES.iterdir() if (p / "app.py").exists())
    failed = []
    for name in names:
        ok, out = verify(EXAMPLES / name, args.source, args.installer, args.python, args.live, args.dist)
        print(
            f"[{'PASS' if ok else 'FAIL'}] {name} ({args.installer}, source={args.source}, py{args.python})"
        )
        print("    " + "\n    ".join(out.strip().splitlines()[-6:]))
        if not ok:
            failed.append(name)
    print("all consumer examples passed" if not failed else f"FAILED: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
