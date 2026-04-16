"""XMLDSig enveloped signature for UBL 2.1 documents."""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

from .certificate import Certificate

# Namespace URIs
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"
_NS_EXT = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"

_NSMAP = {
    "ext": _NS_EXT,
    "ds": _NS_DS,
}


def _ds(tag: str) -> str:
    """Create a ds: qualified name."""
    return f"{{{_NS_DS}}}{tag}"


class XmlSigner:
    """Signs XML with XMLDSig enveloped signature.

    Implements the exact signature structure required by SUNAT:
    - Exclusive C14N canonicalization
    - SHA-256 digest and RSA-SHA256 signing
    - Enveloped signature transform
    - ds:Signature placed inside ext:ExtensionContent

    Usage::

        from xfep.sign import XmlSigner, Certificate

        cert = Certificate.from_file("company.p12", "secret")
        signed_xml = XmlSigner.sign(unsigned_xml_bytes, cert)
    """

    DIGEST_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256"
    SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    C14N_METHOD = "http://www.w3.org/2001/10/xml-exc-c14n#"
    ENVELOPED_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

    @staticmethod
    def sign(xml_bytes: bytes, certificate: Certificate) -> bytes:
        """Sign XML with enveloped XMLDSig signature.

        Algorithm:
        1. Parse XML and locate ext:ExtensionContent placeholder
        2. Build ds:Signature skeleton
        3. Insert ds:Signature into ExtensionContent
        4. Compute DigestValue (remove sig, exc-c14n doc, SHA-256)
        5. Compute SignatureValue (exc-c14n SignedInfo, RSA-SHA256)
        6. Populate KeyInfo with X509 certificate
        7. Serialize to UTF-8 bytes

        Args:
            xml_bytes: Unsigned XML document as bytes.
            certificate: A loaded Certificate instance.

        Returns:
            Signed XML as UTF-8 bytes with XML declaration.

        Raises:
            ValueError: If ExtensionContent placeholder not found.
        """
        # 1. Parse XML
        parser = etree.XMLParser(remove_blank_text=False)
        root = etree.fromstring(xml_bytes, parser)

        # 2. Locate ext:ExtensionContent
        ext_contents = root.xpath("//ext:ExtensionContent", namespaces=_NSMAP)
        if not ext_contents:
            raise ValueError(
                "ext:ExtensionContent element not found in XML. "
                "The XML must contain an UBLExtensions placeholder."
            )
        ext_content = ext_contents[0]

        # 3. Build ds:Signature skeleton
        ds_nsmap = {"ds": _NS_DS}

        sig_elem = etree.SubElement(ext_content, _ds("Signature"), nsmap=ds_nsmap)
        sig_elem.set("Id", "SignST")

        # SignedInfo — needs its own nsmap so exc-c14n can resolve the
        # ds: prefix when canonicalizing SignedInfo as a standalone subtree.
        signed_info = etree.SubElement(
            sig_elem, _ds("SignedInfo"), nsmap=ds_nsmap
        )

        c14n_method = etree.SubElement(signed_info, _ds("CanonicalizationMethod"))
        c14n_method.set("Algorithm", XmlSigner.C14N_METHOD)

        sig_method = etree.SubElement(signed_info, _ds("SignatureMethod"))
        sig_method.set("Algorithm", XmlSigner.SIGNATURE_METHOD)

        reference = etree.SubElement(signed_info, _ds("Reference"))
        reference.set("URI", "")

        transforms = etree.SubElement(reference, _ds("Transforms"))

        transform_env = etree.SubElement(transforms, _ds("Transform"))
        transform_env.set("Algorithm", XmlSigner.ENVELOPED_TRANSFORM)

        transform_c14n = etree.SubElement(transforms, _ds("Transform"))
        transform_c14n.set("Algorithm", XmlSigner.C14N_METHOD)

        digest_method = etree.SubElement(reference, _ds("DigestMethod"))
        digest_method.set("Algorithm", XmlSigner.DIGEST_METHOD)

        digest_value = etree.SubElement(reference, _ds("DigestValue"))

        # SignatureValue placeholder
        sig_value = etree.SubElement(sig_elem, _ds("SignatureValue"))

        # KeyInfo
        key_info = etree.SubElement(sig_elem, _ds("KeyInfo"))
        x509_data = etree.SubElement(key_info, _ds("X509Data"))
        x509_cert_elem = etree.SubElement(x509_data, _ds("X509Certificate"))
        x509_cert_elem.text = certificate.cert_der_b64

        # 4. Compute DigestValue
        # Temporarily remove ds:Signature from document
        ext_content.remove(sig_elem)

        # Exclusive C14N of the entire document
        c14n_bytes = etree.tostring(root, method="c14n", exclusive=True)

        # SHA-256 hash
        digest = hashlib.sha256(c14n_bytes).digest()
        digest_value.text = base64.b64encode(digest).decode("ascii")

        # Re-insert ds:Signature
        ext_content.append(sig_elem)

        # 5. Compute SignatureValue
        # Exclusive C14N of SignedInfo — include ds prefix so namespace
        # declaration appears on the canonicalized element even though it
        # was inherited from a parent in the tree.
        signed_info_c14n = etree.tostring(
            signed_info, method="c14n", exclusive=True
        )

        # RSA-SHA256 sign with PKCS1v15
        signature_bytes = certificate.private_key.sign(
            signed_info_c14n,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        sig_value.text = base64.b64encode(signature_bytes).decode("ascii")

        # 6. Serialize to UTF-8 bytes
        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True,
        )
