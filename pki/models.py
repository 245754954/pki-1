import textwrap
import mongoengine
import logging
import binascii
import OpenSSL
import hashlib
import base64

from bson import Binary
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

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


class Certificate(mongoengine.DynamicDocument):
    pid = mongoengine.ObjectIdField()
    created = mongoengine.DateTimeField(default=datetime.utcnow)
    key = PrivateKeyField()
    cert = CertField()
    serial_number = mongoengine.StringField()
    revoked = mongoengine.BooleanField()
    revoked_at = mongoengine.DateTimeField()

    @property
    def sha1(self):
        return ":".join(textwrap.wrap(binascii.hexlify(self.cert.fingerprint(hashes.SHA1())).decode(), 2)).upper()

    @property
    def sha256(self):
        return ":".join(textwrap.wrap(binascii.hexlify(self.cert.fingerprint(hashes.SHA256())).decode(), 2)).upper()

    @property
    def keyid(self):
        der_bytes = self.cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        alg = hashlib.sha256()
        alg.update(der_bytes)
        digest = alg.digest()[:30]
        raw_text = base64.b32encode(digest).decode('utf-8').rstrip("=")
        keyid = ":".join(textwrap.wrap(raw_text, 4))
        return keyid

    @property
    def sn(self):
        hex_str = "%x" % self.cert.serial_number
        if len(hex_str) % 2:
            hex_str = "0" + hex_str
        return ":".join(textwrap.wrap(hex_str, 2)).upper()

    @property
    def cn(self):
        for item in self.cert.subject:
            if item.oid == x509.NameOID.COMMON_NAME:
                return item.value

    @property
    def skid(self):
        try:
            item = self.cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            return ":".join(textwrap.wrap(binascii.hexlify(item.value.digest).decode(), 2)).upper()
        except x509.extensions.ExtensionNotFound as e:
            return None

    @property
    def aid(self):
        try:
            item = self.cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            return ":".join(textwrap.wrap(binascii.hexlify(item.value.key_identifier).decode(), 2)).upper()
        except x509.extensions.ExtensionNotFound as e:
            return None


    @property
    def is_ca(self):
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.BASIC_CONSTRAINTS:
                return item.value._ca

    @property
    def is_server(self):
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.EXTENDED_KEY_USAGE:
                return x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in item.value

    @property
    def is_client(self):
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.EXTENDED_KEY_USAGE:
                return x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in item.value

    @property
    def pkcs12(self):
        """
        可以简单的认为 PKCS12 就是把 key, cert, ca certs 全部都打包到一起
        :return:
        """
        pkcs = OpenSSL.crypto.PKCS12()

        pkcs.set_privatekey(OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM,
            self.key.private_bytes(
                serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        ))

        pkcs.set_certificate(OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            self.cert.public_bytes(
                serialization.Encoding.PEM
            )
        ))

        ca_certificates = []
        crt = self
        while crt.pid:
            crt = Certificate.objects(id=crt.pid).get()
            ca_certificates.append(
                OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    crt.cert.public_bytes(
                        serialization.Encoding.PEM
                    )
                )
            )
        if len(ca_certificates):
            pkcs.set_ca_certificates(ca_certificates)

        return pkcs

    @property
    def openssh_public_key(self):
        try:
            return self.cert.public_key().public_bytes(
                format=serialization.PublicFormat.OpenSSH,
                encoding=serialization.Encoding.OpenSSH
            ).decode()
        except Exception as e:
            return "N/A"

    @property
    def pem_public_key(self):
        try:
            return self.cert.public_key().public_bytes(
                format=serialization.PublicFormat.PKCS1,
                encoding=serialization.Encoding.PEM
            ).decode()
        except Exception as e:
            return "N/A"

    @property
    def is_pair_match(self):
        """
        validate if certificate and key's public key is the same
        :return:
        """
        try:
            return self.cert.public_key().public_bytes(
                format=serialization.PublicFormat.PKCS1,
                encoding=serialization.Encoding.DER
            ) == self.key.public_key().public_bytes(
                format=serialization.PublicFormat.PKCS1,
                encoding=serialization.Encoding.DER
            )
        except Exception as e:
            logger.error(e)
            return False

    @property
    def cert_pem(self):
        return self.cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
