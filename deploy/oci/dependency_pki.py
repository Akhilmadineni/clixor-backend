#!/usr/bin/env python3
"""Create and publish the OCI deployment's private dependency certificates.

The long-lived CA is deliberately kept at the legacy ca.key/ca.crt paths.  Each
TLS endpoint receives its own key and leaf certificate.  Leaf and runtime
generations are switched with an atomic relative symlink replacement so a
reader can never observe a key from one generation with a certificate from
another.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence


STATE_VERSION = "1"
DEFAULT_LEAF_DAYS = 397
DEFAULT_RENEW_BEFORE_DAYS = 30
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class PKIError(RuntimeError):
    """A safe-to-report PKI lifecycle error."""


@dataclass(frozen=True)
class RuntimeFile:
    source_name: str
    destination_name: str
    mode: int


@dataclass(frozen=True)
class LeafSpec:
    name: str
    common_name: str
    sans: tuple[str, ...]
    runtime_service: str
    runtime_gid: int
    runtime_files: tuple[RuntimeFile, ...]


LEAF_SPECS = (
    LeafSpec(
        name="dependency-tls",
        common_name="clixor-tls",
        sans=("clixor-tls", "dependency-tls"),
        runtime_service="dependency-tls",
        runtime_gid=99,
        runtime_files=(RuntimeFile("server.pem", "server.pem", 0o440),),
    ),
    LeafSpec(
        name="postgres",
        common_name="postgres.clixor.internal",
        sans=("postgres.clixor.internal",),
        runtime_service="postgres",
        runtime_gid=70,
        runtime_files=(
            RuntimeFile("server.key", "server.key", 0o440),
            RuntimeFile("server.crt", "server.crt", 0o440),
        ),
    ),
    LeafSpec(
        name="nats",
        common_name="nats.clixor.internal",
        sans=("nats.clixor.internal",),
        runtime_service="nats",
        runtime_gid=1000,
        runtime_files=(
            RuntimeFile("server.key", "server.key", 0o440),
            RuntimeFile("server.crt", "server.crt", 0o440),
        ),
    ),
)

STATE_KEYS = ("ca",) + tuple(spec.runtime_service for spec in LEAF_SPECS)


def _run_openssl(
    arguments: Sequence[str], *, input_bytes: Optional[bytes] = None
) -> bytes:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
    except OSError as error:
        raise PKIError("OpenSSL is unavailable") from error
    if completed.returncode != 0:
        operation = arguments[0] if arguments else "operation"
        # OpenSSL diagnostics can include sensitive filenames or input.  Keep
        # deployment logs deliberately generic and never relay its stderr.
        raise PKIError(f"OpenSSL {operation} operation failed")
    return completed.stdout


def _lexists(path: Path) -> bool:
    return os.path.lexists(str(path))


def _require_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise PKIError(f"required PKI file is missing: {path.name}") from error
    if not path.is_file() or path.is_symlink():
        raise PKIError(f"PKI path must be a regular file: {path.name}")
    if metadata.st_nlink != 1:
        raise PKIError(f"PKI file must not have multiple hard links: {path.name}")


def _ensure_directory(
    path: Path,
    mode: int,
    *,
    uid: Optional[int] = None,
    gid: Optional[int] = None,
) -> None:
    if _lexists(path):
        if path.is_symlink() or not path.is_dir():
            raise PKIError(f"PKI path must be a directory: {path.name}")
    else:
        path.mkdir(mode=mode)
    os.chmod(path, mode)
    if uid is not None and gid is not None:
        os.chown(path, uid, gid)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(
    path: Path,
    contents: bytes,
    mode: int,
    *,
    uid: Optional[int] = None,
    gid: Optional[int] = None,
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        if uid is not None and gid is not None:
            os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_symlink(target: str, link_path: Path) -> None:
    temporary_path = link_path.parent / f".{link_path.name}.{uuid.uuid4().hex}"
    try:
        os.symlink(target, temporary_path)
        os.replace(temporary_path, link_path)
        _fsync_directory(link_path.parent)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _public_key_digest_from_key(key_path: Path) -> str:
    public_der = _run_openssl(
        ["pkey", "-in", str(key_path), "-pubout", "-outform", "DER"]
    )
    return hashlib.sha256(public_der).hexdigest()


def _public_key_digest_from_certificate(certificate_path: Path) -> str:
    public_pem = _run_openssl(
        ["x509", "-in", str(certificate_path), "-pubkey", "-noout"]
    )
    public_der = _run_openssl(
        ["pkey", "-pubin", "-outform", "DER"], input_bytes=public_pem
    )
    return hashlib.sha256(public_der).hexdigest()


def _certificate_digest(certificate_path: Path) -> str:
    certificate_der = _run_openssl(
        ["x509", "-in", str(certificate_path), "-outform", "DER"]
    )
    return "sha256:" + hashlib.sha256(certificate_der).hexdigest()


def _certificate_valid_for(certificate_path: Path, seconds: int) -> bool:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    completed = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate_path),
            "-checkend",
            str(seconds),
            "-noout",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=environment,
    )
    return completed.returncode == 0


def _certificate_dns_names(certificate_path: Path) -> tuple[str, ...]:
    try:
        decoded = ssl._ssl._test_decode_cert(str(certificate_path))  # type: ignore[attr-defined]
    except (OSError, ValueError, ssl.SSLError) as error:
        raise PKIError("could not decode a dependency certificate") from error
    return tuple(
        value
        for name_type, value in decoded.get("subjectAltName", ())
        if name_type == "DNS"
    )


def _validate_ca(
    ca_key: Path, ca_certificate: Path, *, required_validity_seconds: int
) -> str:
    _require_regular_file(ca_key)
    _require_regular_file(ca_certificate)
    if _public_key_digest_from_key(ca_key) != _public_key_digest_from_certificate(
        ca_certificate
    ):
        raise PKIError("CA certificate and private key do not match")
    _run_openssl(
        [
            "verify",
            "-check_ss_sig",
            "-CAfile",
            str(ca_certificate),
            str(ca_certificate),
        ]
    )
    if not _certificate_valid_for(ca_certificate, required_validity_seconds):
        raise PKIError(
            "CA expires too soon for a full leaf lifetime; perform a coordinated CA rollover"
        )
    return _certificate_digest(ca_certificate)


def _create_ca(
    pki_root: Path,
    *,
    uid: Optional[int],
    gid: Optional[int],
    required_validity_seconds: int,
) -> tuple[Path, Path, str]:
    temporary_root = Path(tempfile.mkdtemp(prefix=".ca-generation.", dir=pki_root))
    os.chmod(temporary_root, 0o700)
    ca_key = temporary_root / "ca.key"
    ca_certificate = temporary_root / "ca.crt"
    config = temporary_root / "ca.cnf"
    try:
        config.write_text(
            "[req]\n"
            "distinguished_name=dn\n"
            "prompt=no\n"
            "x509_extensions=v3_ca\n"
            "[dn]\n"
            "CN=Clixor OCI Internal CA\n"
            "[v3_ca]\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid:always,issuer\n"
            "basicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,cRLSign\n",
            encoding="ascii",
        )
        os.chmod(config, 0o600)
        _run_openssl(
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(ca_key),
            ]
        )
        _run_openssl(
            [
                "req",
                "-x509",
                "-new",
                "-sha256",
                "-days",
                "3650",
                "-key",
                str(ca_key),
                "-config",
                str(config),
                "-out",
                str(ca_certificate),
            ]
        )
        os.chmod(ca_key, 0o600)
        os.chmod(ca_certificate, 0o644)
        digest = _validate_ca(
            ca_key,
            ca_certificate,
            required_validity_seconds=required_validity_seconds,
        )
        if uid is not None and gid is not None:
            os.chown(ca_key, uid, gid)
            os.chown(ca_certificate, uid, gid)
        for path in (ca_key, ca_certificate):
            with path.open("rb") as source:
                os.fsync(source.fileno())
        # Both replacements are same-filesystem and individually atomic.  A
        # crash between them is detected as an incomplete CA and fails closed;
        # an existing CA is never replaced or repaired automatically.
        destination_key = pki_root / "ca.key"
        destination_certificate = pki_root / "ca.crt"
        os.replace(ca_key, destination_key)
        _fsync_directory(pki_root)
        os.replace(ca_certificate, destination_certificate)
        _fsync_directory(pki_root)
        return destination_key, destination_certificate, digest
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def _ensure_ca(
    pki_root: Path,
    *,
    uid: Optional[int],
    gid: Optional[int],
    required_validity_seconds: int,
) -> tuple[Path, Path, str]:
    ca_key = pki_root / "ca.key"
    ca_certificate = pki_root / "ca.crt"
    key_exists = _lexists(ca_key)
    certificate_exists = _lexists(ca_certificate)
    if key_exists != certificate_exists:
        raise PKIError("CA is incomplete; refusing to generate or replace CA material")
    if not key_exists:
        ca_key, ca_certificate, digest = _create_ca(
            pki_root,
            uid=uid,
            gid=gid,
            required_validity_seconds=required_validity_seconds,
        )
    else:
        digest = _validate_ca(
            ca_key,
            ca_certificate,
            required_validity_seconds=required_validity_seconds,
        )
        os.chmod(ca_key, 0o600)
        os.chmod(ca_certificate, 0o644)
        if uid is not None and gid is not None:
            os.chown(ca_key, uid, gid)
            os.chown(ca_certificate, uid, gid)

    fingerprint_path = pki_root / "ca.fingerprint"
    if _lexists(fingerprint_path):
        _require_regular_file(fingerprint_path)
        try:
            pinned_digest = fingerprint_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise PKIError("could not read the pinned CA fingerprint") from error
        if not SHA256_RE.fullmatch(pinned_digest):
            raise PKIError("pinned CA fingerprint is malformed")
        if pinned_digest != digest:
            raise PKIError("CA fingerprint changed; refusing an implicit trust rollover")
        os.chmod(fingerprint_path, 0o600)
        if uid is not None and gid is not None:
            os.chown(fingerprint_path, uid, gid)
    else:
        _atomic_write(
            fingerprint_path,
            (digest + "\n").encode("ascii"),
            0o600,
            uid=uid,
            gid=gid,
        )
    return ca_key, ca_certificate, digest


def _leaf_current_generation(leaf_root: Path) -> Optional[Path]:
    current = leaf_root / "current"
    if not _lexists(current):
        return None
    if not current.is_symlink():
        raise PKIError(f"{leaf_root.name} current generation must be a symlink")
    target = os.readlink(current)
    parts = Path(target).parts
    if len(parts) != 2 or parts[0] != "generations" or parts[1] in ("", ".", ".."):
        raise PKIError(f"{leaf_root.name} current generation target is unsafe")
    generation = leaf_root / target
    if generation.is_symlink() or not generation.is_dir():
        raise PKIError(f"{leaf_root.name} current generation is missing")
    return generation


def _validate_leaf(
    generation: Path,
    spec: LeafSpec,
    ca_certificate: Path,
    *,
    renew_before_seconds: int,
) -> tuple[str, str]:
    key_path = generation / "server.key"
    certificate_path = generation / "server.crt"
    pem_path = generation / "server.pem"
    for path in (key_path, certificate_path, pem_path):
        _require_regular_file(path)
    if _public_key_digest_from_key(key_path) != _public_key_digest_from_certificate(
        certificate_path
    ):
        raise PKIError(f"{spec.name} certificate and private key do not match")
    _run_openssl(
        [
            "verify",
            "-purpose",
            "sslserver",
            "-CAfile",
            str(ca_certificate),
            str(certificate_path),
        ]
    )
    if tuple(sorted(_certificate_dns_names(certificate_path))) != tuple(
        sorted(spec.sans)
    ):
        raise PKIError(f"{spec.name} certificate SANs do not match its endpoint")
    if not _certificate_valid_for(certificate_path, renew_before_seconds):
        raise PKIError(f"{spec.name} certificate is inside its renewal window")
    expected_pem = key_path.read_bytes().rstrip(b"\n") + b"\n" + certificate_path.read_bytes()
    if pem_path.read_bytes() != expected_pem:
        raise PKIError(f"{spec.name} combined PEM does not match its key and certificate")
    return _certificate_digest(certificate_path), _public_key_digest_from_key(key_path)


def _secure_leaf_generation(
    generation: Path, *, uid: Optional[int], gid: Optional[int]
) -> None:
    if generation.is_symlink() or not generation.is_dir():
        raise PKIError("dependency leaf generation must be a directory")
    os.chmod(generation, 0o700)
    if uid is not None and gid is not None:
        os.chown(generation, uid, gid)
    for filename, mode in (
        ("server.key", 0o600),
        ("server.crt", 0o644),
        ("server.pem", 0o600),
    ):
        path = generation / filename
        _require_regular_file(path)
        os.chmod(path, mode)
        if uid is not None and gid is not None:
            os.chown(path, uid, gid)


def _generate_leaf(
    leaf_root: Path,
    spec: LeafSpec,
    ca_key: Path,
    ca_certificate: Path,
    *,
    leaf_days: int,
    renew_before_seconds: int,
    uid: Optional[int],
    gid: Optional[int],
) -> tuple[Path, str, str]:
    generations = leaf_root / "generations"
    temporary_generation = Path(
        tempfile.mkdtemp(prefix=".generation.", dir=str(generations))
    )
    os.chmod(temporary_generation, 0o700)
    key_path = temporary_generation / "server.key"
    certificate_path = temporary_generation / "server.crt"
    csr_path = temporary_generation / "server.csr"
    config_path = temporary_generation / "server.cnf"
    pem_path = temporary_generation / "server.pem"
    try:
        san_entries = ",".join(f"DNS:{name}" for name in spec.sans)
        config_path.write_text(
            "[v3_server]\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName={san_entries}\n",
            encoding="ascii",
        )
        os.chmod(config_path, 0o600)
        _run_openssl(
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(key_path),
            ]
        )
        _run_openssl(
            [
                "req",
                "-new",
                "-sha256",
                "-key",
                str(key_path),
                "-subj",
                f"/CN={spec.common_name}",
                "-out",
                str(csr_path),
            ]
        )
        serial = max(1, int.from_bytes(os.urandom(20), "big") >> 1)
        _run_openssl(
            [
                "x509",
                "-req",
                "-sha256",
                "-days",
                str(leaf_days),
                "-set_serial",
                f"0x{serial:x}",
                "-in",
                str(csr_path),
                "-CA",
                str(ca_certificate),
                "-CAkey",
                str(ca_key),
                "-extfile",
                str(config_path),
                "-extensions",
                "v3_server",
                "-out",
                str(certificate_path),
            ]
        )
        pem_path.write_bytes(
            key_path.read_bytes().rstrip(b"\n") + b"\n" + certificate_path.read_bytes()
        )
        for path, mode in (
            (key_path, 0o600),
            (certificate_path, 0o644),
            (pem_path, 0o600),
        ):
            os.chmod(path, mode)
            if uid is not None and gid is not None:
                os.chown(path, uid, gid)
            with path.open("rb") as source:
                os.fsync(source.fileno())
        digest, public_key_digest = _validate_leaf(
            temporary_generation,
            spec,
            ca_certificate,
            renew_before_seconds=renew_before_seconds,
        )
        generation_name = digest.removeprefix("sha256:")
        generation = generations / generation_name
        if _lexists(generation):
            raise PKIError(f"unexpected duplicate {spec.name} certificate generation")
        # Remove transient signing inputs before the immutable generation is
        # made visible.  The CSR is not secret, but it has no runtime purpose.
        csr_path.unlink()
        config_path.unlink()
        os.replace(temporary_generation, generation)
        _fsync_directory(generations)
        _atomic_symlink(f"generations/{generation_name}", leaf_root / "current")
        return generation, digest, public_key_digest
    finally:
        shutil.rmtree(temporary_generation, ignore_errors=True)


def _ensure_leaf(
    leaves_root: Path,
    spec: LeafSpec,
    ca_key: Path,
    ca_certificate: Path,
    *,
    leaf_days: int,
    renew_before_seconds: int,
    uid: Optional[int],
    gid: Optional[int],
) -> tuple[Path, str, str, bool]:
    leaf_root = leaves_root / spec.name
    _ensure_directory(leaf_root, 0o700, uid=uid, gid=gid)
    _ensure_directory(leaf_root / "generations", 0o700, uid=uid, gid=gid)
    generation = _leaf_current_generation(leaf_root)
    if generation is not None:
        try:
            _secure_leaf_generation(generation, uid=uid, gid=gid)
            digest, public_key_digest = _validate_leaf(
                generation,
                spec,
                ca_certificate,
                renew_before_seconds=renew_before_seconds,
            )
            return generation, digest, public_key_digest, False
        except PKIError:
            # A malformed, mismatched, incorrectly scoped, or expiring leaf is
            # safe to replace because the pinned CA remains unchanged.
            pass
    generation, digest, public_key_digest = _generate_leaf(
        leaf_root,
        spec,
        ca_key,
        ca_certificate,
        leaf_days=leaf_days,
        renew_before_seconds=renew_before_seconds,
        uid=uid,
        gid=gid,
    )
    return generation, digest, public_key_digest, True


def _publish_runtime_generation(
    runtime_root: Path,
    generation: Path,
    digest: str,
    spec: LeafSpec,
    *,
    chown_runtime: bool,
) -> bool:
    service_root = runtime_root / f"{spec.runtime_service}-tls"
    # dependency-tls already carries its suffix in the service name.
    if spec.runtime_service == "dependency-tls":
        service_root = runtime_root / "dependency-tls"
    runtime_uid = 0 if chown_runtime else None
    runtime_gid = spec.runtime_gid if chown_runtime else None
    _ensure_directory(service_root, 0o750, uid=runtime_uid, gid=runtime_gid)
    generations = service_root / ".generations"
    _ensure_directory(generations, 0o750, uid=runtime_uid, gid=runtime_gid)
    generation_name = digest.removeprefix("sha256:")
    destination = generations / generation_name
    if not _lexists(destination):
        temporary = Path(tempfile.mkdtemp(prefix=".generation.", dir=generations))
        try:
            os.chmod(temporary, 0o750)
            if runtime_uid is not None and runtime_gid is not None:
                os.chown(temporary, runtime_uid, runtime_gid)
            for runtime_file in spec.runtime_files:
                source = generation / runtime_file.source_name
                _require_regular_file(source)
                target = temporary / runtime_file.destination_name
                descriptor = os.open(
                    str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, runtime_file.mode
                )
                try:
                    os.fchmod(descriptor, runtime_file.mode)
                    if runtime_uid is not None and runtime_gid is not None:
                        os.fchown(descriptor, runtime_uid, runtime_gid)
                    with source.open("rb") as input_file, os.fdopen(
                        descriptor, "wb"
                    ) as output_file:
                        descriptor = -1
                        shutil.copyfileobj(input_file, output_file)
                        output_file.flush()
                        os.fsync(output_file.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            os.replace(temporary, destination)
            _fsync_directory(generations)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    if destination.is_symlink() or not destination.is_dir():
        raise PKIError(f"runtime {spec.runtime_service} generation is unsafe")
    for runtime_file in spec.runtime_files:
        source = generation / runtime_file.source_name
        target = destination / runtime_file.destination_name
        _require_regular_file(target)
        if source.read_bytes() != target.read_bytes():
            raise PKIError(f"runtime {spec.runtime_service} generation is immutable")
        metadata = target.stat()
        if metadata.st_mode & 0o777 != runtime_file.mode:
            raise PKIError(f"runtime {spec.runtime_service} file mode changed")
        if runtime_uid is not None and runtime_gid is not None:
            if metadata.st_uid != runtime_uid or metadata.st_gid != runtime_gid:
                raise PKIError(f"runtime {spec.runtime_service} ownership changed")

    current = service_root / "current"
    desired_target = f".generations/{generation_name}"
    if _lexists(current):
        if not current.is_symlink():
            raise PKIError(f"runtime {spec.runtime_service} current must be a symlink")
        if os.readlink(current) == desired_target:
            return False
    _atomic_symlink(desired_target, current)
    return True


def _canonical_state(state: Mapping[str, str]) -> bytes:
    if set(state) != set(STATE_KEYS):
        raise PKIError("dependency PKI state has unexpected keys")
    for value in state.values():
        if not SHA256_RE.fullmatch(value):
            raise PKIError("dependency PKI state contains a malformed digest")
    lines = [f"version {STATE_VERSION}"]
    lines.extend(f"{key} {state[key]}" for key in STATE_KEYS)
    return ("\n".join(lines) + "\n").encode("ascii")


def read_state(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise PKIError(f"could not read dependency PKI state: {path.name}") from error
    if not lines or lines[0] != f"version {STATE_VERSION}":
        raise PKIError("dependency PKI state version is invalid")
    state: dict[str, str] = {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 2:
            raise PKIError("dependency PKI state line is invalid")
        key, digest = fields
        if key in state or key not in STATE_KEYS or not SHA256_RE.fullmatch(digest):
            raise PKIError("dependency PKI state entry is invalid")
        state[key] = digest
    _canonical_state(state)
    return state


def pending_restarts(desired_path: Path, applied_path: Path) -> list[str]:
    desired = read_state(desired_path)
    if not _lexists(applied_path):
        return [spec.runtime_service for spec in LEAF_SPECS]
    applied = read_state(applied_path)
    if desired["ca"] != applied["ca"]:
        return [spec.runtime_service for spec in LEAF_SPECS]
    return [
        spec.runtime_service
        for spec in LEAF_SPECS
        if desired[spec.runtime_service] != applied[spec.runtime_service]
    ]


def mark_applied(desired_path: Path, applied_path: Path) -> None:
    desired = read_state(desired_path)
    _atomic_write(applied_path, _canonical_state(desired), 0o600)


def ensure_dependency_pki(
    pki_root: Path,
    runtime_root: Path,
    *,
    leaf_days: int = DEFAULT_LEAF_DAYS,
    renew_before_seconds: int = DEFAULT_RENEW_BEFORE_DAYS * 86400,
    chown_runtime: bool = True,
    pki_uid: Optional[int] = 0,
    pki_gid: Optional[int] = 0,
    leaf_specs: Iterable[LeafSpec] = LEAF_SPECS,
) -> tuple[dict[str, str], list[str]]:
    if leaf_days < 2:
        raise PKIError("leaf lifetime must be at least two days")
    if renew_before_seconds < 0:
        raise PKIError("renewal window must not be negative")
    specs = tuple(leaf_specs)
    if tuple(spec.runtime_service for spec in specs) != tuple(
        spec.runtime_service for spec in LEAF_SPECS
    ):
        raise PKIError("dependency PKI service set is invalid")
    _ensure_directory(pki_root, 0o700, uid=pki_uid, gid=pki_gid)
    _ensure_directory(runtime_root, 0o750)
    lock_path = pki_root / ".dependency-pki.lock"
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    descriptor = os.open(str(lock_path), lock_flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if pki_uid is not None and pki_gid is not None:
            os.fchown(descriptor, pki_uid, pki_gid)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        required_ca_validity = (leaf_days * 86400) + renew_before_seconds
        ca_key, ca_certificate, ca_digest = _ensure_ca(
            pki_root,
            uid=pki_uid,
            gid=pki_gid,
            required_validity_seconds=required_ca_validity,
        )
        leaves_root = pki_root / "leaves"
        _ensure_directory(leaves_root, 0o700, uid=pki_uid, gid=pki_gid)
        state = {"ca": ca_digest}
        public_key_digests: dict[str, str] = {}
        rotated: list[str] = []
        leaf_generations: dict[str, Path] = {}
        for spec in specs:
            generation, digest, public_key_digest, leaf_rotated = _ensure_leaf(
                leaves_root,
                spec,
                ca_key,
                ca_certificate,
                leaf_days=leaf_days,
                renew_before_seconds=renew_before_seconds,
                uid=pki_uid,
                gid=pki_gid,
            )
            state[spec.runtime_service] = digest
            public_key_digests[spec.runtime_service] = public_key_digest
            leaf_generations[spec.runtime_service] = generation
            if leaf_rotated:
                rotated.append(spec.runtime_service)
        if len(set(public_key_digests.values())) != len(public_key_digests):
            raise PKIError("dependency certificates must use distinct private keys")

        for spec in specs:
            runtime_rotated = _publish_runtime_generation(
                runtime_root,
                leaf_generations[spec.runtime_service],
                state[spec.runtime_service],
                spec,
                chown_runtime=chown_runtime,
            )
            if runtime_rotated and spec.runtime_service not in rotated:
                rotated.append(spec.runtime_service)
        _atomic_write(
            runtime_root / "dependency-pki.desired",
            _canonical_state(state),
            0o600,
            uid=pki_uid,
            gid=pki_gid,
        )
        return state, rotated
    finally:
        os.close(descriptor)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    ensure_parser = subparsers.add_parser("ensure")
    ensure_parser.add_argument("--pki-root", type=Path, required=True)
    ensure_parser.add_argument("--runtime-root", type=Path, required=True)
    ensure_parser.add_argument(
        "--leaf-days", type=int, default=DEFAULT_LEAF_DAYS
    )
    ensure_parser.add_argument(
        "--renew-before-days", type=int, default=DEFAULT_RENEW_BEFORE_DAYS
    )

    pending_parser = subparsers.add_parser("pending-restarts")
    pending_parser.add_argument("--desired", type=Path, required=True)
    pending_parser.add_argument("--applied", type=Path, required=True)

    applied_parser = subparsers.add_parser("mark-applied")
    applied_parser.add_argument("--desired", type=Path, required=True)
    applied_parser.add_argument("--applied", type=Path, required=True)
    return parser


def main(arguments: Optional[Sequence[str]] = None) -> int:
    os.umask(0o077)
    parser = _build_parser()
    options = parser.parse_args(arguments)
    try:
        if options.command == "ensure":
            if os.geteuid() != 0:
                raise PKIError("dependency PKI installation must run as root")
            _, rotated = ensure_dependency_pki(
                options.pki_root,
                options.runtime_root,
                leaf_days=options.leaf_days,
                renew_before_seconds=options.renew_before_days * 86400,
            )
            summary = ",".join(rotated) if rotated else "none"
            print(f"Dependency PKI ready; rotated endpoints: {summary}")
        elif options.command == "pending-restarts":
            print(" ".join(pending_restarts(options.desired, options.applied)))
        elif options.command == "mark-applied":
            mark_applied(options.desired, options.applied)
        else:  # pragma: no cover - argparse constrains this branch.
            raise PKIError("unknown dependency PKI command")
    except PKIError as error:
        print(f"dependency PKI error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
