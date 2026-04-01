"""Allow running with: python -m strix.web"""

from strix.web import run_server

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8420)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
