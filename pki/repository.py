import logging
from flask import render_template, request, Blueprint, make_response, abort
from cryptography.hazmat.primitives import serialization

from pki.models import Certificate

logger = logging.getLogger(__name__)

bp = Blueprint("repository", __name__)


@bp.route("/")
def home():
    """
    certificate policies homepage
    :return:
    """
    certificates = [
        item for item in Certificate.objects() if item.is_ca and item.key
    ]
    return render_template("repository/index.html", certificates=certificates)


@bp.route("/<id>.<file_format>")
def download(id, file_format):
    """
    download ca certificate
    :param id:
    :return:
    """
    cert = Certificate.objects(id=id).get()

    # only ca can be downloaded
    if not cert.is_ca:
        abort(404)

    response = make_response("")

    if file_format == "crt":
        response = make_response(cert.cert.public_bytes(
            serialization.Encoding.PEM
        ))
        response.headers['Content-Type'] = 'application/x-x509-ca-cert'
        response.headers['Content-Disposition'] = f'attachment; filename={id}.crt'
    elif file_format == "der":
        response = make_response(cert.cert.public_bytes(
            serialization.Encoding.DER
        ))
        response.headers['Content-Type'] = 'application/x-x509-ca-cert'
        response.headers['Content-Disposition'] = f'attachment; filename={id}.der'
    elif file_format == "crl":
        # openssl crl -in certificate.crl --text -noout
        response = make_response(cert.crl.public_bytes(
            serialization.Encoding.PEM
        ))
        response.headers['Content-Type'] = 'application/pkix-crl'
        response.headers['Content-Disposition'] = f'attachment; filename={id}.crl'
    else:
        abort(404)

    return response
