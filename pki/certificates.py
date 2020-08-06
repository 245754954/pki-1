import logging
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from ipaddress import IPv4Address
from flask import render_template, redirect, url_for, flash, request, Blueprint, make_response
from cryptography.hazmat.primitives import serialization

from pki.forms import CreateCertificateForm, ConfirmForm
from pki.models import Certificate

logger = logging.getLogger(__name__)

bp = Blueprint("certificates", __name__)


@bp.route("/")
def home():
    """
    List
    :return:
    """
    certificates = Certificate.objects()
    return render_template("index.html", certificates=certificates)


@bp.route("/create", methods=["POST", "GET"])
def create():
    """
    Create
    :return:
    """
    parent_id = request.args.get("parent")
    parent_cert = Certificate.objects(id=parent_id).first() if parent_id else None

    form = CreateCertificateForm(
        data={
            "parent": parent_cert.cert.serial_number if parent_cert else 0,
            "is_ca": False if parent_cert else True,
            "cn": "example.com" if parent_cert else "Example Root CA",
        }
    )

    if form.validate_on_submit():
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # serial number
        serial_number = x509.random_serial_number()

        # subject
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, form.c.data),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, form.st.data),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, form.l.data),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, form.o.data),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, form.ou.data),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, form.cn.data),
        ])

        # issuer
        issuer = parent_cert.cert.issuer if parent_cert else subject

        signing_key = parent_cert.key if parent_cert else key
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=int(form.duration.data))
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier(
                x509.extensions._key_identifier_from_public_key(signing_key.public_key()),
                None,
                None
            ), critical=False
        )

        # basic constraints
        cert = cert.add_extension(
            x509.BasicConstraints(form.is_ca.data, None), critical=False
        )

        # ocsp
        cert = cert.add_extension(
            x509.AuthorityInformationAccess([
                # openssl x509 -in 95285781730451486911577519787958288522332983584.crt -ocsp_uri -noout
                x509.AccessDescription(
                    x509.OID_OCSP,
                    x509.UniformResourceIdentifier(url_for(".ocsp_response", _external=True))),
                x509.AccessDescription(
                    x509.OID_CA_ISSUERS,
                    x509.UniformResourceIdentifier(
                        url_for(".home", _external=True)))
            ]), critical=False
        )

        # key_usage
        if form.is_ca.data:
            cert = cert.add_extension(
                x509.KeyUsage(
                    # 数字签名
                    digital_signature=True,
                    # 认可签名
                    content_commitment=False,
                    # 秘钥加密
                    key_encipherment=False,
                    # 数据加密
                    data_encipherment=False,
                    # 秘钥协商
                    key_agreement=False,
                    # 证书签名
                    key_cert_sign=True,
                    # CRL 签名
                    crl_sign=True,
                    # 仅加密
                    encipher_only=False,
                    # 仅解密
                    decipher_only=False,
                ), critical=True
            )
        else:
            cert = cert.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )

        # extended_key_usage
        extended_key_usage = []
        if form.server_auth.data:
            extended_key_usage.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)
        if form.client_auth.data:
            extended_key_usage.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
        if form.is_ca.data:
            extended_key_usage.append(x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING)

        if len(extended_key_usage):
            cert = cert.add_extension(
                x509.ExtendedKeyUsage(extended_key_usage), critical=False
            )

        # subject alternative name
        san = []
        for item in form.san.data.split("\n"):
            if item:
                try:
                    ipaddress = IPv4Address(item)
                    san.append(x509.IPAddress(ipaddress))
                except Exception as e:
                    logger.info(e)
                    san.append(x509.DNSName(item))
        if len(san):
            cert = cert.add_extension(
                x509.SubjectAlternativeName(san), critical=False
            )

        # sign
        cert = cert.sign(signing_key, hashes.SHA256(), default_backend())

        c = Certificate(
            key=key,
            cert=cert,
            serial_number=str(serial_number)
        )

        if parent_cert:
            c.pid = parent_cert.id

        c.save()

        flash(f"Create successful")

        return redirect(url_for(".home"))

    return render_template("create.html", form=form)


@bp.route("/<id>")
def detail(id):
    """
    Detail
    :param id:
    :return:
    """
    cert = Certificate.objects(id=id).get()
    return render_template("detail.html", crt=cert, cert=cert.cert, item=cert)


@bp.route("/<id>/delete", methods=["POST", "GET"])
def delete(id):
    """
    Delete
    :param id:
    :return:
    """

    form = ConfirmForm()
    cert = Certificate.objects(id=id).get()

    if form.validate_on_submit():
        cert.delete()
        flash("Delete successful")
        return redirect(url_for(".home"))

    return render_template("confirm.html", form=form, message="This certificate will be PERMANENTLY deleted.")


@bp.route("/<id>/export/<format>")
def export(id, format):
    """
    Export
    :return:
    """
    cert = Certificate.objects(id=id).get()
    sn = cert.cert.serial_number

    # 参照 MIME
    # application/pkcs8                   .p8  .key
    # application/x-x509-ca-cert          .crt .der
    # application/x-x509-user-cert        .crt
    # application/x-pkcs7-crl             .crl
    # application/x-pem-file              .pem
    # application/pkcs12                  .pfx .p12

    if format == "crt":
        # openssl x509 -text -noout -in certificate.crt
        response = make_response(cert.cert.public_bytes(
            serialization.Encoding.PEM
        ))
        response.headers['Content-Type'] = 'application/x-x509-ca-cert'
        response.headers['Content-Disposition'] = f'attachment; filename={sn}.crt'
    elif format == "crt-chain":
        buffer = bytearray()
        while True:
            buffer.extend(cert.cert.public_bytes(
                serialization.Encoding.PEM
            ))
            if not cert.pid:
                break
            cert = Certificate.objects(id=cert.pid).get()
        response = make_response(bytes(buffer))
        response.headers['Content-Type'] = 'application/x-x509-ca-cert'
        response.headers['Content-Disposition'] = f'attachment; filename={sn}.crt'
    elif format == "key":
        response = make_response(cert.key.private_bytes(
            serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        response.headers['Content-Type'] = 'application/x-pem-file'
        response.headers['Content-Disposition'] = f'attachment; filename={sn}.key'
    elif format == "pkcs12":
        # openssl pkcs12 -nodes -in me.p12
        response = make_response(cert.pkcs12.export())
        response.headers['Content-Type'] = 'application/pkcs12'
        response.headers['Content-Disposition'] = f'attachment; filename={sn}.p12'
    return response


@bp.route("/<id>/revoke", methods=["POST", "GET"])
def revoke(id):
    """
    Delete
    :param id:
    :return:
    """

    form = ConfirmForm()
    cert = Certificate.objects(id=id).get()

    if form.validate_on_submit():
        cert.update(
            revoked=True,
            revoked_at=datetime.utcnow()
        )
        flash("revoke successful")
        return redirect(url_for(".home"))

    return render_template("confirm.html", form=form, message="This certificate will be REVOKED.")


@bp.route("/ocsp", methods=["POST", "GET"])
@bp.route("/ocsp/<id>", methods=["POST", "GET"])
def ocsp_response(id):
    import base64
    req = ocsp.load_der_ocsp_request(request.data or base64.b64decode(id))
    cert = Certificate.objects(serial_number=str(req.serial_number)).get()
    ca_cert = Certificate.objects(id=cert.pid).get()

    builder = ocsp.OCSPResponseBuilder()

    if cert.revoked:
        builder = builder.add_response(
            cert=cert.cert,
            issuer=cert.cert,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=datetime.utcnow(),
            next_update=datetime.utcnow(),
            revocation_time=cert.revoked_at,
            revocation_reason=None
        )
    else:
        builder = builder.add_response(
            cert=cert.cert,
            issuer=cert.cert,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=datetime.utcnow(),
            next_update=datetime.utcnow(),
            revocation_time=None,
            revocation_reason=None
        )

    builder = builder.responder_id(
        ocsp.OCSPResponderEncoding.HASH, ca_cert.cert
    )
    response_object = builder.sign(ca_cert.key, hashes.SHA256())
    response = make_response(response_object.public_bytes(
        serialization.Encoding.DER
    ))
    response.headers['Content-Type'] = 'application/ocsp-response'

    return response
