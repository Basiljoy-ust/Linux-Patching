"""Shared paths, constants and the API logger.

Moved out of main.py unchanged (refactor/split-backend).
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)

api_logger = logging.getLogger("linux_patching.api")
api_logger.setLevel(logging.INFO)
api_logger.propagate = False

if not api_logger.handlers:
    file_handler = RotatingFileHandler(
        LOG_DIR / "api.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    api_logger.addHandler(file_handler)


ANSIBLE_DIR = BASE_DIR / "ansible"
ANSIBLE_INVENTORY = ANSIBLE_DIR / "inventory.ini"
LOCAL_INVENTORY_HOSTS = {"localhost", "Linux-patching1"}
# Re-tune once RHEL preflight steps have been measured on real hosts.
DISCOVERY_TIMEOUT_SECONDS = int(os.environ.get("PATCH_DISCOVERY_TIMEOUT", "180"))
PATCH_JOB_TIMEOUT_SECONDS = int(os.environ.get("PATCH_JOB_TIMEOUT", "900"))
ANSIBLE_VAULT_PASSWORD_FILE = Path(
    os.environ.get(
        "ANSIBLE_VAULT_PASSWORD_FILE",
        str(Path.home() / ".config" / "linux-patching" / "vault-password"),
    )
)
