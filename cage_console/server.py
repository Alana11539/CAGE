"""Console entry point: ``python -m cage_console.server --logs runs --results results``."""

from __future__ import annotations

import argparse

from .app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the CAGE Console")
    parser.add_argument("--logs", default="runs", help="directory of JSONL decision logs")
    parser.add_argument("--results", default="results", help="directory of CAGE-Eval exports")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(create_app(args.logs, args.results), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
