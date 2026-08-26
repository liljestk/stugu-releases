#!/usr/bin/env python3
"""Refresh the short-lived TUF roles (snapshot, timestamp) of the Stugu feed.

Snapshot and timestamp are TUF's designated online roles; root and targets
remain offline-signed and are never modified here. The refresher:

  1. loads the trusted root and the current metadata set;
  2. refuses to run if root or targets themselves need the offline ceremony,
     since refreshing the online roles cannot help then;
  3. bumps snapshot (+90 days) and timestamp (+30 days) by exactly one
     version each, preserving the snapshot hash/length pins in timestamp;
  4. signs with keys supplied via environment variables, refusing any key
     whose keyid the trusted root does not list for that role; and
  5. proves the result by running a full python-tuf client update from the
     trusted root before anything is written back.

Keys are securesystemslib ed25519 private-key JSON documents provided via
STUGU_TUF_SNAPSHOT_KEY and STUGU_TUF_TIMESTAMP_KEY. Nothing here creates,
prints, or stores key material.

`--self-test` builds a throwaway repository with throwaway keys in a temp
directory and runs the complete refresh + client verification against it, so
the logic is provable without real keys.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
# Internal client API; acceptable because the workflow pins tuf==7.0.0 and the
# self-test exercises this exact path on every run.
from tuf.ngclient.config import EnvelopeType
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet

SNAPSHOT_LIFETIME = dt.timedelta(days=90)
TIMESTAMP_LIFETIME = dt.timedelta(days=30)
OFFLINE_CEREMONY_WARNING = dt.timedelta(days=30)
EXIT_OFFLINE_CEREMONY_NEEDED = 3


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def load(directory: Path, name: str) -> Metadata:
    return Metadata.from_bytes((directory / name).read_bytes())


def signer_from_env(variable: str, root: Root, role: str) -> CryptoSigner:
    """Build a signer from a PKCS#8 PEM private key, or a securesystemslib
    key document, whichever the environment variable holds.

    The signing keys are stored as PEM (``-----BEGIN PRIVATE KEY-----``), so
    that is the primary path; the JSON form is still accepted because other
    Stugu tooling emits it. In both cases the public half is derived and its
    keyid checked against the trusted root before the key is used, so a key
    belonging to another role can never sign here.
    """
    raw = os.environ.get(variable)
    if not raw or not raw.strip():
        raise SystemExit(f"{variable} is not set; provide the {role} private key")
    material = raw.strip()

    if "BEGIN" in material and "PRIVATE KEY" in material:
        try:
            private_key = serialization.load_pem_private_key(
                material.encode("utf-8"), password=None
            )
        except (ValueError, TypeError) as error:
            raise SystemExit(
                f"{variable} is not a readable unencrypted PEM private key: {error}"
            ) from error
        public_key = SSlibKey.from_crypto(private_key.public_key())
        return CryptoSigner(private_key, public_key)

    try:
        document = json.loads(material)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"{variable} is neither a PEM private key nor a key document: {error}"
        ) from error
    return CryptoSigner.from_securesystemslib_key(document)


def verify_signer_for_role(root: Root, role: str, signer) -> None:
    """Refuse a signer whose keyid the trusted root does not list for role."""
    keyid = signer.public_key.keyid
    if keyid not in root.roles[role].keyids:
        raise SystemExit(
            f"signer keyid {keyid[:16]}... is not authorized for role {role}"
        )


def refresh(metadata_dir: Path, snapshot_signer, timestamp_signer,
            now: dt.datetime) -> dict:
    root_meta = load(metadata_dir, "1.root.json")
    root: Root = root_meta.signed
    verify_signer_for_role(root, "snapshot", snapshot_signer)
    verify_signer_for_role(root, "timestamp", timestamp_signer)
    root_expires = root.expires.replace(tzinfo=dt.timezone.utc)
    if root_expires < now + OFFLINE_CEREMONY_WARNING:
        print(f"REFUSING: root expires {root_expires}; offline ceremony required")
        raise SystemExit(EXIT_OFFLINE_CEREMONY_NEEDED)

    timestamp_meta = load(metadata_dir, "timestamp.json")
    old_snapshot_version = timestamp_meta.signed.snapshot_meta.version
    snapshot_meta = load(metadata_dir, f"{old_snapshot_version}.snapshot.json")

    targets_version = snapshot_meta.signed.meta["targets.json"].version
    targets_meta = load(metadata_dir, f"{targets_version}.targets.json")
    targets_expires = targets_meta.signed.expires.replace(tzinfo=dt.timezone.utc)
    if targets_expires < now:
        print(
            f"REFUSING: targets v{targets_version} expired {targets_expires}; "
            "offline ceremony required"
        )
        raise SystemExit(EXIT_OFFLINE_CEREMONY_NEEDED)
    targets_ceremony_soon = targets_expires < now + OFFLINE_CEREMONY_WARNING

    # Bump snapshot by exactly one version with a fresh lifetime.
    new_snapshot: Snapshot = snapshot_meta.signed
    new_snapshot.version = old_snapshot_version + 1
    new_snapshot.expires = now + SNAPSHOT_LIFETIME
    snapshot_meta.signatures.clear()
    snapshot_meta.sign(snapshot_signer)

    serializer = JSONSerializer(compact=False)
    snapshot_bytes = snapshot_meta.to_bytes(serializer)

    # Timestamp pins the new snapshot by version, length, and hash, matching
    # the existing feed's pinning style.
    new_timestamp: Timestamp = timestamp_meta.signed
    new_timestamp.version = new_timestamp.version + 1
    new_timestamp.expires = now + TIMESTAMP_LIFETIME
    new_timestamp.snapshot_meta = MetaFile(
        version=new_snapshot.version,
        length=len(snapshot_bytes),
        hashes={"sha256": hashlib.sha256(snapshot_bytes).hexdigest()},
    )
    timestamp_meta.signatures.clear()
    timestamp_meta.sign(timestamp_signer)
    timestamp_bytes = timestamp_meta.to_bytes(serializer)

    # Client-side proof: a fresh python-tuf client starting from the trusted
    # root must accept the refreshed chain. This is exactly what the appliance
    # does, so nothing is written unless this passes.
    trusted = TrustedMetadataSet(
        (metadata_dir / "1.root.json").read_bytes(), EnvelopeType.METADATA
    )
    trusted.update_timestamp(timestamp_bytes)
    trusted.update_snapshot(snapshot_bytes)
    trusted.update_targets(targets_meta.to_bytes(serializer))
    print("client verification: trusted root accepted the refreshed chain")

    (metadata_dir / f"{new_snapshot.version}.snapshot.json").write_bytes(
        snapshot_bytes
    )
    (metadata_dir / "timestamp.json").write_bytes(timestamp_bytes)
    return {
        "snapshot": new_snapshot.version,
        "timestamp": new_timestamp.version,
        "snapshot_expires": new_snapshot.expires.isoformat(),
        "timestamp_expires": new_timestamp.expires.isoformat(),
        "targets_ceremony_soon": targets_ceremony_soon,
        "targets_expires": targets_expires.isoformat(),
    }


def self_test() -> None:
    """Build a throwaway repo with throwaway keys; run the full refresh."""
    workspace = Path(tempfile.mkdtemp(prefix="stugu-tuf-selftest-"))
    try:
        metadata_dir = workspace / "metadata"
        metadata_dir.mkdir()
        now = utcnow()
        serializer = JSONSerializer(compact=False)
        signers = {}
        for role in ("root", "targets", "snapshot", "timestamp"):
            signers[role] = CryptoSigner.generate_ed25519()

        root = Root(version=1, expires=now + dt.timedelta(days=3650))
        for role in ("root", "targets", "snapshot", "timestamp"):
            root.add_key(signers[role].public_key, role)
        root_meta = Metadata(root)
        root_meta.sign(signers["root"])
        (metadata_dir / "1.root.json").write_bytes(root_meta.to_bytes(serializer))

        targets = Targets(version=4, expires=now + dt.timedelta(days=20))
        targets_meta = Metadata(targets)
        targets_meta.sign(signers["targets"])
        (metadata_dir / "4.targets.json").write_bytes(
            targets_meta.to_bytes(serializer)
        )

        snapshot = Snapshot(version=9, expires=now - dt.timedelta(days=7))
        snapshot.meta = {"targets.json": MetaFile(version=4)}
        snapshot_meta_obj = Metadata(snapshot)
        snapshot_meta_obj.sign(signers["snapshot"])
        snapshot_bytes = snapshot_meta_obj.to_bytes(serializer)
        (metadata_dir / "9.snapshot.json").write_bytes(snapshot_bytes)

        timestamp = Timestamp(version=9, expires=now - dt.timedelta(days=14))
        timestamp.snapshot_meta = MetaFile(
            version=9,
            length=len(snapshot_bytes),
            hashes={"sha256": hashlib.sha256(snapshot_bytes).hexdigest()},
        )
        timestamp_meta_obj = Metadata(timestamp)
        timestamp_meta_obj.sign(signers["timestamp"])
        (metadata_dir / "timestamp.json").write_bytes(
            timestamp_meta_obj.to_bytes(serializer)
        )

        # The starting state mirrors the incident: snapshot and timestamp both
        # expired, targets valid but inside the ceremony-warning window.
        result = refresh(
            metadata_dir, signers["snapshot"], signers["timestamp"], now
        )
        assert result["snapshot"] == 10 and result["timestamp"] == 10, result
        assert result["targets_ceremony_soon"] is True, result

        # Refreshing an already-fresh repo must also work (the weekly case).
        result2 = refresh(
            metadata_dir, signers["snapshot"], signers["timestamp"], now
        )
        assert result2["snapshot"] == 11 and result2["timestamp"] == 11, result2

        # A signer the root does not trust must be refused before signing.
        rogue = CryptoSigner.generate_ed25519()
        try:
            refresh(metadata_dir, rogue, signers["timestamp"], now)
        except SystemExit as error:
            print(f"rogue snapshot signer correctly rejected: {error}")
        else:
            raise AssertionError("rogue signer was not rejected")
        # The real keys are PKCS#8 PEM files, so prove that path too: a PEM
        # for the snapshot role must load and produce the same keyid the root
        # authorizes, and a PEM belonging to another role must be refused.
        from cryptography.hazmat.primitives import serialization as _serialization

        def _pem_of(signer) -> str:
            return signer._private_key.private_bytes(  # noqa: SLF001
                _serialization.Encoding.PEM,
                _serialization.PrivateFormat.PKCS8,
                _serialization.NoEncryption(),
            ).decode("utf-8")

        os.environ["STUGU_SELFTEST_SNAPSHOT_PEM"] = _pem_of(signers["snapshot"])
        root_signed = load(metadata_dir, "1.root.json").signed
        pem_signer = signer_from_env(
            "STUGU_SELFTEST_SNAPSHOT_PEM", root_signed, "snapshot"
        )
        assert pem_signer.public_key.keyid == signers["snapshot"].public_key.keyid
        refresh(metadata_dir, pem_signer, signers["timestamp"], now)
        print("PEM private key accepted and produced the authorized keyid")

        os.environ["STUGU_SELFTEST_WRONG_PEM"] = _pem_of(signers["targets"])
        wrong = signer_from_env(
            "STUGU_SELFTEST_WRONG_PEM", root_signed, "snapshot"
        )
        try:
            refresh(metadata_dir, wrong, signers["timestamp"], now)
        except SystemExit as error:
            print(f"wrong-role PEM correctly rejected: {error}")
        else:
            raise AssertionError("wrong-role PEM was not rejected")

        print("SELF-TEST PASSED")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata-dir", type=Path, default=Path("host-updates/v1/metadata")
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    root: Root = load(args.metadata_dir, "1.root.json").signed
    snapshot_signer = signer_from_env("STUGU_TUF_SNAPSHOT_KEY", root, "snapshot")
    timestamp_signer = signer_from_env(
        "STUGU_TUF_TIMESTAMP_KEY", root, "timestamp"
    )
    result = refresh(args.metadata_dir, snapshot_signer, timestamp_signer, utcnow())
    print(json.dumps(result, indent=2))
    if result["targets_ceremony_soon"]:
        print(
            f"WARNING: targets expires {result['targets_expires']}; "
            "schedule the offline targets ceremony",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_OFFLINE_CEREMONY_NEEDED)


if __name__ == "__main__":
    main()
