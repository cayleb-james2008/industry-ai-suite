"""Command-line entry point for the live SentinelDesk public-context review."""

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from suite_core import OpenAICompatibleClient
from .flow import run_live


def _witnessed_client(base_url: str) -> OpenAICompatibleClient:
    route = urlsplit(base_url)
    try:
        port = route.port
    except ValueError:
        port = None
    if (route.scheme != "http" or route.hostname != "127.0.0.1" or port in (None, 18180)
            or route.path != "/v1" or route.username or route.password or route.query or route.fragment):
        raise ValueError("AI URL must be the piece-owned loopback witness proxy at /v1, not the model-server port")
    default_trace = Path.home() / ".local/state/industry-ai-suite/ai-traces.jsonl"
    trace_path = Path(os.environ.get("SUITE_AI_TRACE_PATH", str(default_trace))).expanduser()
    if not trace_path.is_absolute():
        raise ValueError("SUITE_AI_TRACE_PATH must be an absolute private output path")
    return OpenAICompatibleClient(
        base_url, model="industry-suite-local", allowed_hosts=("127.0.0.1",),
        trace_path=trace_path, timeout=150.0,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review the live CISA KEV catalog as public context, not organization alerts."
    )
    parser.add_argument("--ai-url", help="piece-owned loopback witness proxy URL ending in /v1")
    args = parser.parse_args(argv)
    ai_client = _witnessed_client(args.ai_url) if args.ai_url else None
    result = run_live(ai_client=ai_client)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED_SOURCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
