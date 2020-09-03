import logging
from datetime import datetime
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
from flask import request, Blueprint, make_response
from cryptography.hazmat.primitives import serialization

from pki.models import Certificate

logger = logging.getLogger(__name__)

bp = Blueprint("ocsp", __name__)


@bp.route("/", methods=["POST", "GET"])
@bp.route("/<id>", methods=["POST", "GET"])
def ocsp_response(id=None):
    '''
    payload could be found in
     - request.data
     - path

    :param id:
    :return:
    '''

    payload = request.data or id
    if not payload:
        # @todo return invalid ocsp response
        return "This OCSP Endpoint"

    req = ocsp.load_der_ocsp_request(payload)
    cert = Certificate.objects(serial_number=str(req.serial_number)).get()
    ca_cert = Certificate.objects(id=cert.pid).get()

    builder = ocsp.OCSPResponseBuilder()

    if cert.revoked:
        builder = builder.add_response(
            cert=cert.cert,
            issuer=ca_cert.cert,
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
            issuer=ca_cert.cert,
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
