#!/usr/bin/python3
"""Render local staging files for path-only Compose secret consumption."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().with_name("hydrate-vault-secrets.py")
SPEC = importlib.util.spec_from_file_location("clixor_vault_hydrator", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("staging secret preparation failed")
HYDRATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HYDRATOR)
SECRET_ROOT = Path("/srv/clixor/secrets")


def read_regular(name: str) -> bytes:
    path = SECRET_ROOT / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise HYDRATOR.HydrationError(f"staging source is unsafe: {name}")
    content = path.read_bytes()
    if not content or len(content) > HYDRATOR.MAX_ENV_BYTES:
        raise HYDRATOR.HydrationError(f"staging source size is invalid: {name}")
    return content


def main(argv: list[str]) -> int:
    if argv or os.geteuid() != 0:
        print("staging secret preparation requires root and accepts no arguments", file=sys.stderr)
        return 2
    os.umask(0o077)
    try:
        HYDRATOR._validate_secret_root(SECRET_ROOT, 0, 0)
        api_content = read_regular("api.env")
        postgres_content = read_regular("postgres.env")
        redis_content = read_regular("redis.env")
        nats_content = read_regular("nats.env")
        grafana_content = read_regular("grafana.env")
        api = HYDRATOR._parse_env(
            api_content,
            "api_env",
            HYDRATOR.API_ALLOWED_KEYS,
            frozenset(
                {
                    "CLUSTER_ENV",
                    "CLUSTER_DATABASE_URL",
                    "CLUSTER_DATABASE_MAX_CONNS",
                    "CLUSTER_DATABASE_MIN_CONNS",
                    "CLUSTER_TLS_CA_FILE",
                    "CLUSTER_REDIS_URL",
                    "CLUSTER_NATS_URL",
                    "CLUSTER_METRICS_TOKEN",
                }
            ),
        )
        if api["CLUSTER_ENV"] == b"production":
            raise HYDRATOR.HydrationError("local staging files cannot select production")
        postgres_keys = frozenset({"POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"})
        postgres = HYDRATOR._parse_env(
            postgres_content, "postgres_env", postgres_keys, postgres_keys
        )
        redis_keys = frozenset({"REDIS_PASSWORD"})
        redis = HYDRATOR._parse_env(redis_content, "redis_env", redis_keys, redis_keys)
        nats_keys = frozenset({"NATS_AUTH_TOKEN"})
        nats = HYDRATOR._parse_env(nats_content, "nats_env", nats_keys, nats_keys)
        grafana_keys = frozenset({"GF_SECURITY_ADMIN_USER", "GF_SECURITY_ADMIN_PASSWORD"})
        grafana = HYDRATOR._parse_env(
            grafana_content, "grafana_env", grafana_keys, grafana_keys
        )
        HYDRATOR._validate_dependency_consistency(api, postgres, redis, nats)
        if (
            HYDRATOR.SERVICE_NAME_RE.fullmatch(grafana["GF_SECURITY_ADMIN_USER"]) is None
            or HYDRATOR.SERVICE_SECRET_RE.fullmatch(grafana["GF_SECURITY_ADMIN_PASSWORD"])
            is None
        ):
            raise HYDRATOR.HydrationError("Grafana credentials have an invalid format")

        stage = Path(tempfile.mkdtemp(prefix=".staging-runtime-", dir=SECRET_ROOT))
        try:
            migrate = HYDRATOR._selected_env(
                api,
                (
                    "CLUSTER_DATABASE_URL",
                    "CLUSTER_DATABASE_MAX_CONNS",
                    "CLUSTER_DATABASE_MIN_CONNS",
                    "CLUSTER_TLS_CA_FILE",
                ),
            )
            postgres_password = postgres["POSTGRES_PASSWORD"]
            redis_password = redis["REDIS_PASSWORD"]
            outputs = {
                "api.env": (api_content, 0o440, 0, 65532),
                "migrate.env": (migrate, 0o440, 0, 65532),
                "metrics.token": (api["CLUSTER_METRICS_TOKEN"], 0o440, 0, 65534),
                "postgres.password": (postgres_password + b"\n", 0o440, 0, 70),
                "postgres.pgpass": (
                    b"postgres.clixor.internal:5432:clixor:clixor:"
                    + postgres_password
                    + b"\n",
                    0o400,
                    0,
                    0,
                ),
                "redis.password": (redis_password + b"\n", 0o440, 0, 1000),
                "redis.acl": (
                    b"user default on >" + redis_password + b" ~* &* +@all\n",
                    0o440,
                    0,
                    1000,
                ),
                "nats.conf": (
                    (
                        "port: 4222\nhttp: 8222\njetstream { store_dir: /data }\n"
                        "authorization { token: "
                        + json.dumps(nats["NATS_AUTH_TOKEN"].decode("ascii"))
                        + " }\n"
                        "tls {\n  cert_file: /run/nats-tls/server.crt\n"
                        "  key_file: /run/nats-tls/server.key\n}\n"
                    ).encode("ascii"),
                    0o440,
                    0,
                    1000,
                ),
                "grafana.ini": (
                    (
                        "[security]\nadmin_user = "
                        + grafana["GF_SECURITY_ADMIN_USER"].decode("ascii")
                        + "\nadmin_password = "
                        + grafana["GF_SECURITY_ADMIN_PASSWORD"].decode("ascii")
                        + "\n[users]\nallow_sign_up = false\n"
                        "[auth.anonymous]\nenabled = false\n"
                        "[server]\nroot_url = http://127.0.0.1:13000\n"
                    ).encode("ascii"),
                    0o440,
                    0,
                    472,
                ),
            }
            for name, (content, mode, uid, gid) in outputs.items():
                HYDRATOR._write_file(stage / name, content, mode, uid, gid)
            HYDRATOR._fsync_directory(stage)
            for name in outputs:
                os.replace(stage / name, SECRET_ROOT / name)
            HYDRATOR._fsync_directory(SECRET_ROOT)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    except (OSError, HYDRATOR.HydrationError):
        print("staging secret preparation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
