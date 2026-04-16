"""Tests for xfep.sign.certificate — PKCS#12 certificate loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

from xfep.sign import Certificate, CertificateError


class TestCertificateFromFile:
    """Spec: Load valid certificate from file path."""

    def test_loads_private_key(self, p12_file: tuple[Path, bytes]) -> None:
        path, password = p12_file
        cert = Certificate.from_file(path, password)
        assert cert.private_key is not None
        assert isinstance(cert.private_key, rsa_module.RSAPrivateKey)

    def test_loads_x509_cert(self, p12_file: tuple[Path, bytes]) -> None:
        path, password = p12_file
        cert = Certificate.from_file(path, password)
        assert cert.x509_cert is not None

    def test_cert_der_b64_non_empty(self, p12_file: tuple[Path, bytes]) -> None:
        path, password = p12_file
        cert = Certificate.from_file(path, password)
        assert isinstance(cert.cert_der_b64, str)
        assert len(cert.cert_der_b64) > 0


class TestCertificateFromBytes:
    """Spec: Load certificate from bytes."""

    def test_loads_identically(self, test_p12_data: tuple[bytes, bytes]) -> None:
        data, password = test_p12_data
        cert = Certificate.from_bytes(data, password)
        assert cert.private_key is not None
        assert cert.x509_cert is not None
        assert len(cert.cert_der_b64) > 0

    def test_accepts_string_password(
        self, test_p12_data: tuple[bytes, bytes]
    ) -> None:
        data, _ = test_p12_data
        cert = Certificate.from_bytes(data, "test1234")
        assert cert.private_key is not None


class TestCertificateErrors:
    """Spec: Invalid file and wrong password raise CertificateError."""

    def test_wrong_password_raises(
        self, test_p12_data: tuple[bytes, bytes]
    ) -> None:
        data, _ = test_p12_data
        with pytest.raises(CertificateError, match="Failed to load certificate"):
            Certificate.from_bytes(data, b"wrong_password")

    def test_invalid_data_raises(self) -> None:
        with pytest.raises(CertificateError, match="Failed to load certificate"):
            Certificate.from_bytes(b"not a pkcs12 file", b"password")

    def test_nonexistent_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CertificateError, match="Failed to read certificate file"):
            Certificate.from_file(tmp_path / "nonexistent.p12", b"password")
