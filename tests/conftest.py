"""Test fixtures for xfep-sign — generates self-signed certificates."""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

TEST_PASSWORD = b"test1234"


@pytest.fixture
def test_p12_data() -> tuple[bytes, bytes]:
    """Generate a self-signed .p12 certificate for testing.

    Returns:
        Tuple of (p12_bytes, password).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test XFEP")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(TEST_PASSWORD),
    )
    return p12_bytes, TEST_PASSWORD


@pytest.fixture
def certificate(test_p12_data: tuple[bytes, bytes]):
    """Return a loaded Certificate instance."""
    from xfep.sign import Certificate

    data, password = test_p12_data
    return Certificate.from_bytes(data, password)


@pytest.fixture
def p12_file(test_p12_data: tuple[bytes, bytes], tmp_path: Path) -> tuple[Path, bytes]:
    """Write .p12 data to a temp file.

    Returns:
        Tuple of (file_path, password).
    """
    data, password = test_p12_data
    p12_path = tmp_path / "test.p12"
    p12_path.write_bytes(data)
    return p12_path, password
