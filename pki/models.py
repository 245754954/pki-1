import textwrap
import mongoengine
import logging
import binascii
import OpenSSL
import base64
import pyotp

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend

from .fields import PrivateKeyField, CertField

logger = logging.getLogger(__name__)


class Certificate(mongoengine.DynamicDocument):
    created = mongoengine.DateTimeField(default=datetime.utcnow)
    key = PrivateKeyField()
    cert = CertField()
    pid = mongoengine.ObjectIdField()
    serial_number = mongoengine.StringField()
    revoked = mongoengine.BooleanField()
    revoked_at = mongoengine.DateTimeField()

    @property
    def sha1(self):
        """
        sha1 fingerprint
        :return:
        """
        return ":".join(textwrap.wrap(binascii.hexlify(self.cert.fingerprint(hashes.SHA1())).decode(), 2)).upper()

    @property
    def sha256(self):
        """
        sha256 fingerprint
        :return:
        """
        return ":".join(textwrap.wrap(binascii.hexlify(self.cert.fingerprint(hashes.SHA256())).decode(), 2)).upper()

    @property
    def keyid(self):
        """
        kid fingerprint
        :return:
        """
        digest = self.cert.fingerprint(hashes.SHA256())[:30]
        keyid = ":".join(textwrap.wrap(base64.b32encode(digest).decode().rstrip("="), 4)).upper()
        return keyid

    @property
    def skid(self):
        """
        subject key identifier SKID
        :return:
        """
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                return ":".join(textwrap.wrap(binascii.hexlify(item.value.digest).decode(), 2)).upper()

    @property
    def akid(self):
        """
        authority key identifier AKID
        :return:
        """
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                return ":".join(textwrap.wrap(binascii.hexlify(item.value.key_identifier).decode(), 2)).upper()

    @property
    def sn(self):
        """
        serial number in hex
        :return:
        """
        hex_str = "{:x}".format(self.cert.serial_number)
        if len(hex_str) % 2:
            hex_str = "0" + hex_str
        return ":".join(textwrap.wrap(hex_str, 2)).upper()

    @property
    def cn(self):
        """
        common name
        :return:
        """
        for item in self.cert.subject:
            if item.oid == x509.NameOID.COMMON_NAME:
                return item.value

    @property
    def is_ca(self):
        """
        basic constraints
        :return:
        """
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.BASIC_CONSTRAINTS:
                return item.value._ca

    @property
    def is_server(self):
        """
        extended key usage for server auth
        :return:
        """
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.EXTENDED_KEY_USAGE:
                return x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in item.value

    @property
    def is_client(self):
        """
        extended key usage for client auth
        :return:
        """
        for item in self.cert.extensions:
            if item.oid == x509.ExtensionOID.EXTENDED_KEY_USAGE:
                return x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in item.value

    @property
    def pkcs12_password(self):
        from flask import current_app
        tp = pyotp.TOTP(current_app.config.get('TOTP_BASE'))
        return tp.generate_otp(tp.timecode(self.cert.not_valid_after))

    @property
    def pkcs12(self):
        """
        export pkcs12
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
    def crl(self):
        builder = (
            x509.CertificateRevocationListBuilder().issuer_name(
                self.cert.subject
            ).last_update(
                datetime.today()
            ).next_update(
                datetime.today() + timedelta(days=1)
            )
        )

        backend = default_backend()

        for item in Certificate.objects(revoked=True, pid=self.id):
            revoked_cert = (
                x509.RevokedCertificateBuilder().serial_number(
                    item.cert.serial_number
                ).revocation_date(
                    datetime.today()
                ).build(backend)
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(
            private_key=self.key,
            algorithm=hashes.SHA256(),
            backend=backend,
        )

        return crl
