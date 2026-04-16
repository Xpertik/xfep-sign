# xfep-sign

Firma digital XMLDSig para Facturación Electrónica Perú (SUNAT).

Parte del [ecosistema XFEP](https://github.com/xpertik). Firma XML generado por [`xfep-xml`](https://github.com/xpertik/xfep-xml) con certificado digital `.p12`/`.pfx`.

## Instalación

```bash
pip install xfep-sign
```

## Uso

```python
from xfep.sign import Certificate, XmlSigner

# Cargar certificado digital (.p12 / .pfx)
cert = Certificate.from_file("empresa.p12", "mi_password")

# Firmar XML (bytes de xfep-xml)
signed_xml = XmlSigner.sign(unsigned_xml_bytes, cert)
# signed_xml es bytes UTF-8 con ds:Signature insertado
```

### Cargar certificado desde bytes

```python
with open("empresa.p12", "rb") as f:
    cert = Certificate.from_bytes(f.read(), "mi_password")
```

### Flujo completo con xfep-xml

```python
from xfep.models import Invoice, Client, Detalle, Company
from xfep.xml import XmlBuilder
from xfep.sign import Certificate, XmlSigner

# 1. Crear modelo
invoice = Invoice(
    company_id=1, branch_id=1, serie="F001",
    fecha_emision="2026-02-10", moneda="PEN",
    tipo_operacion="0101", forma_pago_tipo="Contado",
    client=Client(tipo_documento="6", numero_documento="20123456789", razon_social="CLIENTE SAC"),
    detalles=[Detalle(descripcion="Producto", unidad="NIU", cantidad=1,
                      mto_precio_unitario=118, porcentaje_igv=18, tip_afe_igv="10")],
)

# 2. Generar XML
builder = XmlBuilder()
xml_bytes = builder.build(invoice, company)

# 3. Firmar
cert = Certificate.from_file("empresa.p12", "password")
signed_xml = XmlSigner.sign(xml_bytes, cert)

# signed_xml listo para enviar a SUNAT con xfep-ws
```

## API

### `Certificate`

```python
# Desde archivo
cert = Certificate.from_file(path, password)

# Desde bytes
cert = Certificate.from_bytes(data, password)

# Propiedades
cert.private_key   # cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
cert.x509_cert     # cryptography.x509.Certificate
cert.cert_der_b64  # str — certificado X509 en base64 DER
```

### `XmlSigner`

```python
signed_xml: bytes = XmlSigner.sign(xml_bytes, certificate)
```

- `xml_bytes` — XML sin firmar (bytes UTF-8, debe contener `ext:ExtensionContent` placeholder)
- `certificate` — Instancia de `Certificate`
- Retorna XML firmado como `bytes` (UTF-8)
- Lanza `ValueError` si no encuentra `ext:ExtensionContent`

### `CertificateError`

Excepción para errores de carga de certificado (archivo inválido, password incorrecto, etc.).

## Especificación de firma

La firma XMLDSig insertada sigue la estructura requerida por SUNAT:

| Elemento | Valor |
|----------|-------|
| `ds:Signature/@Id` | `SignST` |
| CanonicalizationMethod | Exclusive C14N (`exc-c14n#`) |
| SignatureMethod | RSA-SHA256 |
| DigestMethod | SHA-256 |
| Transform | Enveloped signature + Exclusive C14N |
| Ubicación | `ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent` |
| KeyInfo | X509Certificate (base64 DER) |

## Desarrollo

```bash
git clone https://github.com/xpertik/xfep-sign.git
cd xfep-sign

python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest -v
```

Los tests generan certificados auto-firmados — no se necesitan archivos externos.

## Stack

- **Python** >= 3.13
- **cryptography** >= 43.0 (PKCS#12, RSA, SHA-256)
- **lxml** >= 5.0 (XML parsing, Exclusive C14N)
- **Build**: Hatchling
- **Tests**: pytest (25 tests)

## Parte del ecosistema XFEP

| Paquete | Estado | Descripción |
|---------|--------|-------------|
| [xfep-models](https://github.com/xpertik/xfep-models) | v0.1.0 | Modelos de datos |
| [xfep-xml](https://github.com/xpertik/xfep-xml) | v0.1.0 | Generación XML UBL 2.1 |
| **xfep-sign** | **v0.1.0** | **Firma digital XMLDSig** |
| xfep-ws | pendiente | Cliente SOAP/REST para SUNAT |
| xfep-parser | pendiente | Parseo de respuestas SUNAT |

## Licencia

MIT
