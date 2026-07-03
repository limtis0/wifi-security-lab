from __future__ import annotations

import os


def require_root() -> None:
    """Abort unless running as root.

    Real wireless operations (monitor mode, channel changes, raw injection)
    need CAP_NET_ADMIN/CAP_NET_RAW, which in practice means root. The Python
    analogue of require_root() in images/base/lib.sh.
    """
    if os.geteuid() != 0:
        raise PermissionError(
            "This must be run as root (real wireless capture and injection "
            "require it). Re-run with sudo, or use --dry-run for a hardware-free run."
        )
