import mongoengine
import logging

from bson import Binary
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class PrivateKeyField(mongoengine.fields.BaseField):
    """
    cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """

    def to_mongo(self, value):
        pass

        return Binary(
            value.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            )
        )

    def to_python(self, value):
        pass

        if value is not None:
            return serialization.load_der_private_key(
                value,
                password=b"passphrase",
                backend=default_backend()
            )


class CertField(mongoengine.fields.BaseField):
    """
    cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """

    def to_mongo(self, value):
        pass

        return Binary(
            value.public_bytes(serialization.Encoding.DER)
        )

    def to_python(self, value):
        pass

        if value is not None:
            return x509.load_der_x509_certificate(
                value,
                backend=default_backend()
            )
