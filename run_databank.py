from __future__ import annotations

import py_compile
import runpy
from pathlib import Path


def main() -> int:
    app_path = Path(__file__).with_name("DATABANK.PY")

    try:
        py_compile.compile(str(app_path), doraise=True)
    except py_compile.PyCompileError as error:
        print("Syntax check failed. App was not started.")
        print(error)
        return 1

    runpy.run_path(str(app_path), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())