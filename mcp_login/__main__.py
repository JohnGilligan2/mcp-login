"""`python -m mcp_login` entry point."""
import logging

import uvicorn

from .app import build_app
from .config import load


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load()
    # proxy_headers + forwarded_allow_ips: a reverse proxy terminates TLS in front of us.
    uvicorn.run(build_app(cfg), host=cfg.host, port=cfg.port,
                proxy_headers=True, forwarded_allow_ips="*", log_level="info")


if __name__ == "__main__":
    main()
