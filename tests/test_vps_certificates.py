import base64
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from commander.database import utcnow
from commander.nodehost import NodeHostError
from commander.vps_certificates import DOMAIN, validate, allowed, export_program


def bundle():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow() - timedelta(days=1))
        .not_valid_after(utcnow() + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    def encode(data):
        return base64.b64encode(data).decode()

    files = {
        "archive/" + DOMAIN + "/fullchain1.pem": encode(
            cert.public_bytes(serialization.Encoding.PEM)
        ),
        "archive/" + DOMAIN + "/privkey1.pem": encode(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
        "live/" + DOMAIN + "/fullchain.pem": {
            "symlink": "../../archive/" + DOMAIN + "/fullchain1.pem"
        },
        "live/" + DOMAIN + "/privkey.pem": {
            "symlink": "../../archive/" + DOMAIN + "/privkey1.pem"
        },
        "renewal/" + DOMAIN + ".conf": encode(b"fixture-only"),
    }
    return files


def test_certbot_lineage_preserves_valid_symlinks_and_matching_key():
    files = bundle()
    result = validate(files)
    assert (
        result["live/" + DOMAIN + "/privkey.pem"]
        == files["live/" + DOMAIN + "/privkey.pem"]
    )
    compile(export_program(), "export-certificate", "exec")


@pytest.mark.parametrize(
    "path",
    [
        "../etc/shadow",
        "live/lt.vetka.rest/privkey.pem",
        "accounts/other/directory/id/private_key.json",
        "/etc/letsencrypt/live/pl.vetka.rest/cert.pem",
    ],
)
def test_certificates_never_escape_selected_domain(path):
    assert not allowed(path)
    files = bundle()
    files[path] = "dGVzdA=="
    with pytest.raises(NodeHostError):
        validate(files)


def test_certificate_symlink_cannot_point_outside_archive():
    files = bundle()
    files["live/" + DOMAIN + "/privkey.pem"] = {"symlink": "../../../../etc/shadow"}
    with pytest.raises(NodeHostError):
        validate(files)
