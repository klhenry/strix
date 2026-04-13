"""Allow running with: python -m strix.web"""

import os
import warnings

# The web server runs scans locally (no Docker-in-Docker), so configure
# standalone mode BEFORE any tool modules are imported.  Tool registration
# happens at import time via @register_tool decorators — if these env vars
# are not set, tools with sandbox_execution=False (create_vulnerability_report,
# finish_scan) will be silently excluded from the registry and the agent will
# never be able to report findings.
os.environ.setdefault("STRIX_SANDBOX_MODE", "true")
os.environ.setdefault("STRIX_STANDALONE", "true")

# Suppress SyntaxWarning from textblob's invalid escape sequences (transitive dep of scrubadub)
warnings.filterwarnings("ignore", category=SyntaxWarning, module=r"textblob\._text")

from strix.web import run_server

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8420)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
