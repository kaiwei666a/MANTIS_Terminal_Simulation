from __future__ import annotations

import os

HOST = "0.0.0.0"
PORT = 2222
HOSTNAME = "Dataset_manage"
SUDO_PASSWORD = os.environ.get("SUDO_PASSWORD", "qwe123")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLASSIFIER_MODEL_DIR = os.path.abspath(os.path.join(
    BASE_DIR,
    os.path.expanduser(os.environ.get("CLASSIFIER_MODEL_DIR") or
                       os.path.join("model", "modernbert_par_2_jaur_1")),
))
RECORDS_DIR = os.path.join(BASE_DIR, "records")
LOGS_DIR = os.path.join(RECORDS_DIR, "logs")
STATE_DIR = os.path.join(RECORDS_DIR, "state")
KEYS_DIR = os.path.join(RECORDS_DIR, "keys")
UPLOADS_DIR = os.path.join(RECORDS_DIR, "uploads")

LOG_FILE = os.path.join(LOGS_DIR, "honeypot.log")
AUTH_LOG = os.path.join(LOGS_DIR, "authentication_log.jsonl")
UPLOAD_AUDIT_JSONL = os.path.join(LOGS_DIR, "upload_audit.jsonl")
SESSION_JSON = os.path.join(STATE_DIR, "session_log.json")
SYSTEM_JSON = os.path.join(STATE_DIR, "system_log.json")

RSA_KEY_PATH = os.path.join(KEYS_DIR, "ssh_host_rsa_key")
ED25519_KEY_PATH = os.path.join(KEYS_DIR, "ssh_host_ed25519_key")
ECDSA_KEY_PATH = os.path.join(KEYS_DIR, "ssh_host_ecdsa_key")

SCP_ROOT = UPLOADS_DIR

DOCKER_UPLOAD_CONTAINER = os.environ.get("DOCKER_UPLOAD_CONTAINER", "terminal_sftp")
DOCKER_UPLOAD_PATH = os.environ.get("DOCKER_UPLOAD_PATH", "/home/sftpuser/upload")
DOCKER_DELETE_LOCAL_AFTER_COPY = (
    os.environ.get("DOCKER_DELETE_LOCAL_AFTER_COPY", "0").strip().lower()
    in {"1", "true", "yes", "on"}
)
UPLOAD_QUARANTINE_DIR = os.path.join(SCP_ROOT, "_quarantine")

DOCKER_DOWNLOAD_CONTAINER = os.environ.get("DOCKER_DOWNLOAD_CONTAINER", "terminal_sftp")
DOCKER_DOWNLOAD_PATH = os.environ.get("DOCKER_DOWNLOAD_PATH", "/downloads")
DOCKER_MAN_CONTAINER = os.environ.get("DOCKER_MAN_CONTAINER", "terminal_man")
DOCKER_MAN_TIMEOUT_SEC = max(1, int(os.environ.get("DOCKER_MAN_TIMEOUT_SEC", "5")))
DOWNLOAD_TIMEOUT_SEC = int(os.environ.get("DOWNLOAD_TIMEOUT_SEC", "15"))
DOWNLOAD_MAX_BYTES = int(
    os.environ.get("DOWNLOAD_MAX_BYTES", str(20 * 1024 * 1024))
)

LOAD_SESSION_FROM_FILE = True
LOAD_SYSTEM_FROM_FILE = True
PERSIST_SYSTEM_TO_FILE = False
TOP_REFRESH_SEC = max(0.5, float(os.getenv("TOP_REFRESH_SEC", "4.0")))


def ensure_runtime_directories() -> None:
    for path in (LOGS_DIR, STATE_DIR, KEYS_DIR, UPLOADS_DIR):
        os.makedirs(path, exist_ok=True)
