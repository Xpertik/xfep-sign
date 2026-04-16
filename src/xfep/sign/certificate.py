"""PKCS#12 certificate loading for XMLDSig signing."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
from cryptography.x509 import Certificate as X509Certificate


class CertificateError(Exception):
    """Raised for certificate loading errors."""


class Certificate:
    """Loads and holds a PKCS#12 (.p12/.pfx) certificate.

    Provides access to the RSA private key, X509 certificate, and
    base64-encoded DER representation for embedding in ds:X509Certificate.

    Usage::

        cert = Certificate.from_file("company.p12", "secret")
        print(cert.cert_der_b64)  # base64 DER for KeyInfo
    """

    def __init__(
        self,
        private_key: object,
        x509_cert: X509Certificate,
    ) -> None:
        self.private_key = private_key
        self.x509_cert = x509_cert

    @property
    def cert_der_b64(self) -> str:
        """Return base64-encoded DER of the X509 certificate."""
        der_bytes = self.x509_cert.public_bytes(Encoding.DER)
        return base64.b64encode(der_bytes).decode("ascii")

    @classmethod
    def from_file(cls, path: str | Path, password: str | bytes) -> Certificate:
        """Load certificate from a .p12/.pfx file.

        Args:
            path: Path to the PKCS#12 file.
            password: Password to decrypt the file.

        Returns:
            A Certificate instance.

        Raises:
            CertificateError: If the file cannot be loaded.
        """
        try:
            data = Path(path).read_bytes()
        except (OSError, IOError) as e:
            raise CertificateError(f"Failed to read certificate file: {e}") from e
        return cls.from_bytes(data, password)

    @classmethod
    def from_bytes(cls, data: bytes, password: str | bytes) -> Certificate:
        """Load certificate from raw .p12/.pfx bytes.

        Args:
            data: Raw PKCS#12 bytes.
            password: Password to decrypt.

        Returns:
            A Certificate instance.

        Raises:
            CertificateError: If the data cannot be parsed.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        try:
            private_key, cert, _ = pkcs12.load_key_and_certificates(data, password)
        except Exception as e:
            raise CertificateError(f"Failed to load certificate: {e}") from e
        if private_key is None or cert is None:
            raise CertificateError(
                "Certificate missing private key or X509 certificate"
            )
        return cls(private_key, cert)
