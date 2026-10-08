from __future__ import annotations

from server.ssh_server import (
    SSHServer,
    install_signal_handlers,
    load_or_create_host_keys,
)
from storage.session_store import configure_logging, log_attack
from terminal_config import HOST, PORT, ensure_runtime_directories


def main() -> None:

    ensure_runtime_directories()
    configure_logging()

    host_keys = load_or_create_host_keys()
    server = SSHServer(host=HOST, port=PORT, host_keys=host_keys)

    install_signal_handlers(server)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log_attack("Shutting down (keyboard interrupt)")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
