"""Lab entrypoint. Refuses to bind anywhere but loopback (unless inside the container)."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping

_DEFAULT_BIND = "127.0.0.1"
_PORT = 8099


def resolve_bind(env: Mapping[str, str]) -> str:
    """Return the bind address, exiting if it would expose the vulnerable lab."""
    bind = env.get("LAB_BIND", _DEFAULT_BIND)
    if env.get("LAB_CONTAINER") == "1":
        return bind  # exposure is then limited by the host-side port publish (127.0.0.1 only)
    try:
        loopback = bind == "localhost" or ipaddress.ip_address(bind).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise SystemExit(
            f"Refusing to bind the intentionally vulnerable lab to {bind!r}: loopback only."
        )
    return bind


def main() -> None:
    import uvicorn

    from target.app import app

    uvicorn.run(app, host=resolve_bind(os.environ), port=_PORT, server_header=False,
                date_header=False, log_level="warning")


if __name__ == "__main__":
    main()
