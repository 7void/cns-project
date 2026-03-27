"""Generate a self-signed RSA 4096-bit TLS certificate for local development.

Saves:
  certs/key.pem  — private key (PEM, unencrypted)
  certs/cert.pem — self-signed certificate (PEM), valid 365 days

Subject Alternative Names cover:
  DNS: localhost
  IP:  127.0.0.1
  IP:  10.109.214.171

Run from the project root:
  python scripts/generate_certs.py
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("ERROR: 'cryptography' package not found. Install it with: pip install cryptography")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CERTS_DIR = os.path.join(PROJECT_ROOT, "certs")
KEY_PATH = os.path.join(CERTS_DIR, "key.pem")
CERT_PATH = os.path.join(CERTS_DIR, "cert.pem")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CERT_VALID_DAYS = 365
KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537

DNS_SANS = ["localhost"]
IP_SANS = ["127.0.0.1", "10.109.214.171"]

# ---------------------------------------------------------------------------
# Generate private key
# ---------------------------------------------------------------------------

print(f"Generating RSA {KEY_SIZE}-bit private key...")
private_key = rsa.generate_private_key(
    public_exponent=PUBLIC_EXPONENT,
    key_size=KEY_SIZE,
)

# ---------------------------------------------------------------------------
# Build certificate
# ---------------------------------------------------------------------------

subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CNS Project Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ]
)

san_entries: list[x509.GeneralName] = [x509.DNSName(name) for name in DNS_SANS]
san_entries += [x509.IPAddress(ipaddress.IPv4Address(ip)) for ip in IP_SANS]

now = datetime.datetime.now(datetime.timezone.utc)

print("Building self-signed certificate...")
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
    .add_extension(
        x509.SubjectAlternativeName(san_entries),
        critical=False,
    )
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

# ---------------------------------------------------------------------------
# Write files
# ---------------------------------------------------------------------------

os.makedirs(CERTS_DIR, exist_ok=True)

with open(KEY_PATH, "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open(CERT_PATH, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

print(f"\n✅ Certificate generated successfully!")
print(f"   Private key : {KEY_PATH}")
print(f"   Certificate : {CERT_PATH}")
print(f"   Valid for   : {CERT_VALID_DAYS} days")
print(f"   SANs (DNS)  : {', '.join(DNS_SANS)}")
print(f"   SANs (IP)   : {', '.join(IP_SANS)}")
print(f"\nRun this script again any time to regenerate (e.g. when cert expires).")
