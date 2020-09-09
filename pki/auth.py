from flask import current_app, request, abort


def check_permission():
    from pki.models import Certificate

    auth_header = current_app.config.get("WEBAUTH_HEADER")

    if auth_header not in request.headers:
        abort(403)
    serial_number = int(f"{request.headers.get(auth_header)}", 16)

    if not Certificate.objects(serial_number=str(serial_number), revoked__ne=True).count():
        abort(403)
