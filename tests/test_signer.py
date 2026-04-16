"""Tests for xfep.sign.signer — XMLDSig enveloped signature."""

from __future__ import annotations

import base64

import pytest
from lxml import etree

from xfep.sign import XmlSigner
from xfep.sign.certificate import Certificate

# Minimal unsigned XML matching xfep-xml invoice template structure
SAMPLE_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
         xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent/>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:ID>F001-1</cbc:ID>
</Invoice>"""

NS = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    "inv": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
}


class TestSignedXmlWellFormedness:
    """Spec: Sign a valid unsigned invoice XML."""

    def test_returns_bytes(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        assert isinstance(result, bytes)

    def test_is_well_formed_xml(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        assert root is not None

    def test_has_xml_declaration(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        assert result.startswith(b"<?xml")

    def test_extension_content_contains_signature(
        self, certificate: Certificate
    ) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        ext_content = root.xpath("//ext:ExtensionContent", namespaces=NS)
        assert len(ext_content) == 1
        sig = ext_content[0].xpath("ds:Signature", namespaces=NS)
        assert len(sig) == 1


class TestSignatureAlgorithms:
    """Spec: Signature uses SHA-256 algorithms."""

    def test_digest_method_sha256(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        digest_methods = root.xpath(
            "//ds:DigestMethod/@Algorithm", namespaces=NS
        )
        assert "http://www.w3.org/2001/04/xmlenc#sha256" in digest_methods

    def test_signature_method_rsa_sha256(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        sig_methods = root.xpath(
            "//ds:SignatureMethod/@Algorithm", namespaces=NS
        )
        assert (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" in sig_methods
        )


class TestCanonicalization:
    """Spec: Canonicalization method is exc-c14n."""

    def test_canonicalization_method_exc_c14n(
        self, certificate: Certificate
    ) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        c14n_methods = root.xpath(
            "//ds:CanonicalizationMethod/@Algorithm", namespaces=NS
        )
        assert "http://www.w3.org/2001/10/xml-exc-c14n#" in c14n_methods

    def test_transform_includes_exc_c14n(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        transform_algs = root.xpath(
            "//ds:Transform/@Algorithm", namespaces=NS
        )
        assert "http://www.w3.org/2001/10/xml-exc-c14n#" in transform_algs


class TestSignaturePlacement:
    """Spec: Signature is placed inside ExtensionContent."""

    def test_signature_inside_extension_content(
        self, certificate: Certificate
    ) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        # ds:Signature must be child of ext:ExtensionContent
        sigs = root.xpath(
            "//ext:ExtensionContent/ds:Signature", namespaces=NS
        )
        assert len(sigs) == 1

    def test_signature_has_id_signst(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        sigs = root.xpath("//ds:Signature", namespaces=NS)
        assert len(sigs) == 1
        assert sigs[0].get("Id") == "SignST"

    def test_no_other_xml_changes(self, certificate: Certificate) -> None:
        """UBLVersionID and ID should remain unchanged."""
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        cbc_ns = {"cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"}
        version = root.xpath("//cbc:UBLVersionID/text()", namespaces=cbc_ns)
        assert version == ["2.1"]
        doc_id = root.xpath("//cbc:ID/text()", namespaces=cbc_ns)
        assert doc_id == ["F001-1"]


class TestSignatureCompleteness:
    """Spec: Signature contains all required sub-elements."""

    def test_has_signed_info(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        assert root.xpath("//ds:Signature/ds:SignedInfo", namespaces=NS)

    def test_has_signature_value(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        sig_vals = root.xpath(
            "//ds:Signature/ds:SignatureValue/text()", namespaces=NS
        )
        assert len(sig_vals) == 1
        assert len(sig_vals[0].strip()) > 0
        # Must be valid base64
        base64.b64decode(sig_vals[0].strip())

    def test_has_key_info_with_x509(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        x509_certs = root.xpath(
            "//ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()",
            namespaces=NS,
        )
        assert len(x509_certs) == 1
        assert len(x509_certs[0].strip()) > 0
        # Must be valid base64
        base64.b64decode(x509_certs[0].strip())

    def test_has_digest_value(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        digest_vals = root.xpath(
            "//ds:DigestValue/text()", namespaces=NS
        )
        assert len(digest_vals) == 1
        assert len(digest_vals[0].strip()) > 0
        # Must be valid base64
        base64.b64decode(digest_vals[0].strip())


class TestEnvelopedTransform:
    """Spec: Enveloped transform is present."""

    def test_enveloped_transform_present(self, certificate: Certificate) -> None:
        result = XmlSigner.sign(SAMPLE_XML, certificate)
        root = etree.fromstring(result)
        transform_algs = root.xpath(
            "//ds:Reference/ds:Transforms/ds:Transform/@Algorithm",
            namespaces=NS,
        )
        assert (
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            in transform_algs
        )


class TestSignerErrors:
    """Edge cases and error handling."""

    def test_missing_extension_content_raises(
        self, certificate: Certificate
    ) -> None:
        xml_no_ext = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">F001-1</cbc:ID>
</Invoice>"""
        with pytest.raises(ValueError, match="ExtensionContent"):
            XmlSigner.sign(xml_no_ext, certificate)
