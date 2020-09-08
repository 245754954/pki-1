import logging
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from ipaddress import IPv4Address
from flask import render_template, redirect, url_for, flash, request, Blueprint, make_response, current_app, jsonify
from cryptography.hazmat.primitives import serialization

from pki.forms import CreateCertificateForm, ConfirmForm, ImportCertificateForm, ScanCertificateForm, \
    UploadCertificateForm
from pki.models import Certificate

logger = logging.getLogger(__name__)

bp = Blueprint("certificates", __name__)


def save_cert_response(x509_cert):
    exist_cert = Certificate.objects(serial_number=str(x509_cert.serial_number)).first()

    # call x509 compare
    if exist_cert and exist_cert.cert == x509_cert:
        flash(f"Certificate {exist_cert.cn} exists")
        return redirect(url_for(".detail", id=exist_cert.id))

    cert = Certificate(
        cert=x509_cert,
        serial_number=str(x509_cert.serial_number)
    )
    cert.save()
    return redirect(url_for(".home"))


@bp.route("/")
def home():
    certificates = Certificate.objects()
    return render_template("index.html", certificates=certificates)


@bp.route("/tree")
def tree_view():
    return render_template("tree.html")


@bp.route("/tree.json")
def tree():
    certificates = [
        {
            'text': item.cn,
            'id': item.skid or str(item.id),
            'parent': (item.akid if item.akid != item.skid else "#") if item.akid else "#",
            'state': {
                'opened': True
            }
        } for item in Certificate.objects()
    ]
    return jsonify(certificates)


@bp.route("/create", methods=["POST", "GET"])
def create():
    """
    Create
    :return:
    """
    parent_id = request.args.get("parent")
    parent_cert = Certificate.objects(id=parent_id).first() if parent_id else None

    form_default_data = {}

    # @todo how to list meta fields
    # @todo rewrite with a intersect
    field_names = [f.name for f in CreateCertificateForm() if hasattr(x509.NameOID, f.name)]

    for field_name in field_names:
        # get default value from environment variables
        form_default_data[field_name] = os.environ.get(f"DEFAULT_{field_name}")
        # get default value from parent certificate if any
        if parent_cert:
            for item in parent_cert.cert.subject:
                if item.oid == getattr(x509.NameOID, field_name):
                    form_default_data[field_name] = item.value

    if parent_cert:
        form = CreateCertificateForm(
            data={
                **form_default_data,

                "duration": int(current_app.config.get("DEFAULT_DURATION")),
                "parent": parent_cert.cert.serial_number,
                "mode": {
                    "is_server_auth": True,
                    "is_client_auth": True,
                },
                "aia": {
                    "enabled": False,
                    'ca_issuers': current_app.config.get("DEFAULT_CA_ISSUER_URL"),
                    'ocsp': current_app.config.get("DEFAULT_OCSP_URL")
                }
            }
        )
    else:
        form = CreateCertificateForm(
            data={
                **form_default_data,

                "duration": 10 * int(current_app.config.get("DEFAULT_DURATION")),
                "parent": 0,
                "mode": {
                    "is_ca": True,
                },
                "aia": {
                    "enabled": False,
                    'ca_issuers': current_app.config.get("DEFAULT_CA_ISSUER_URL"),
                    'ocsp': current_app.config.get("DEFAULT_OCSP_URL")
                }
            }
        )

    if form.validate_on_submit():
        # key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # serial number
        serial_number = x509.random_serial_number()

        # subject
        names = []
        for field_name in field_names:
            if getattr(form, field_name).data:
                names.append(x509.NameAttribute(getattr(x509.NameOID, field_name), getattr(form, field_name).data))
        subject = x509.Name(names)

        # issuer and signing key
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
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False
        )

        # basic constraints
        cert = cert.add_extension(
            x509.BasicConstraints(form.mode.data.get('is_ca'), None), critical=False
        )

        # ocsp
        if form.aia.data.get("enabled"):
            cert = cert.add_extension(
                x509.AuthorityInformationAccess([
                    # openssl x509 -in 95285781730451486911577519787958288522332983584.crt -ocsp_uri -noout
                    x509.AccessDescription(
                        x509.OID_OCSP,
                        x509.UniformResourceIdentifier(form.aia.data.get('ocsp'))),
                    # @todo validate issuers
                    x509.AccessDescription(
                        x509.OID_CA_ISSUERS,
                        x509.UniformResourceIdentifier(form.aia.data.get('ca_issuers')))
                ]), critical=False
            )

        # key_usage
        if form.mode.data.get('is_ca'):
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
        # @todo render all extended key usage
        extended_key_usage = []
        if form.mode.data.get('is_server_auth'):
            extended_key_usage.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)
        if form.mode.data.get('is_client_auth'):
            extended_key_usage.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
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

        # save
        c = Certificate(
            key=key,
            cert=cert,
            serial_number=str(serial_number),
            pid=parent_cert.id if parent_cert else None
        )
        c.save()

        flash(f"Certificate create successful")

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
        #
        # openssl x509 -text -noout -in certificate.crt
        response = make_response(cert.cert.public_bytes(
            serialization.Encoding.PEM
        ))
        response.headers['Content-Type'] = 'application/x-x509-ca-cert'
        response.headers['Content-Disposition'] = f'attachment; filename={sn}.crt'
    elif format == "der":
        #
        # openssl x509 --text -inform DER -noout -in certificate.crt
        response = make_response(cert.cert.public_bytes(
            serialization.Encoding.DER
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
        response = make_response(cert.pkcs12.export(passphrase=cert.pkcs12_password))
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


@bp.route("/import", methods=["POST", "GET"])
def import_certificate():
    """
    :return:
    """
    return render_template("import.html")


@bp.route("/import/text", methods=["POST", "GET"])
def import_by_text():
    """
    :return:
    """
    form = ImportCertificateForm()

    if form.validate_on_submit():

        x509_cert = x509.load_pem_x509_certificate(form.certificate.data.encode(), backend=default_backend())

        cert = Certificate(
            cert=x509_cert,
            serial_number=str(x509_cert.serial_number)
        )

        if form.private_key.data:
            cert.key = serialization.load_pem_private_key(
                form.private_key.data.encode(),
                password=form.password.data.encode() or None,
                backend=default_backend())

            if not cert.is_pair_match:
                flash("Keypair does not match", "Error")
                return redirect(url_for(".home"))

        cert.save()

        return redirect(url_for(".home"))

    return render_template("import_by_text.html", form=form)


@bp.route("/import/upload", methods=["POST", "GET"])
def import_by_upload():
    """
    :return:
    """
    form = UploadCertificateForm()

    if form.validate_on_submit():
        upload_content = request.files['certificate'].read()

        x509_cert = None

        try:
            x509_cert = x509.load_pem_x509_certificate(upload_content, backend=default_backend())
        except Exception as e:
            print(e)

        try:
            x509_cert = x509.load_der_x509_certificate(upload_content, backend=default_backend())
        except Exception as e:
            print(e)

        if not x509_cert:
            flash("Upload error", "error")
            return redirect(url_for(".import_by_upload"))

        return save_cert_response(x509_cert)

    return render_template("import_by_upload.html", form=form)


@bp.route("/import/scan", methods=["POST", "GET"])
def import_by_scan():
    """
    :return:
    """
    import ssl
    from urllib.parse import urlparse
    import socket

    form = ScanCertificateForm()

    if form.validate_on_submit():
        parsed = urlparse(form.url.data)

        hostname = parsed.hostname
        port = int(parsed.port) if parsed.port else 443

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

        sock = context.wrap_socket(conn, server_hostname=hostname)

        sock.connect((hostname, port))

        x509_cert = x509.load_der_x509_certificate(sock.getpeercert(True), backend=default_backend())

        return save_cert_response(x509_cert)

    return render_template("import_by_scan.html", form=form)
