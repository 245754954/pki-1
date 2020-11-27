import os
import logging.config
from flask import Flask, redirect
from flask_bootstrap import Bootstrap
from mongoengine import connect

logging.root.setLevel(logging.DEBUG)
logging.config.fileConfig(os.path.abspath(os.path.join(os.path.dirname(__file__), 'logging.conf')))

logger = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)

    app.config.from_mapping(
        BOOTSTRAP_SERVE_LOCAL=True,
        SECRET_KEY=os.environ.get("SECRET_KEY") or "catfish",
        MONGODB_URL=os.environ.get("MONGODB_URL") or "mongodb://localhost:27017",
        TOTP_BASE=os.environ.get("TOTP_BASE") or "dogbird",
        WEBAUTH_HEADER=os.environ.get('WEBAUTH_HEADER'),

        DEFAULT_DURATION=os.environ.get("DEFAULT_DURATION") or "365",
        DEFAULT_OCSP_URL=os.environ.get("DEFAULT_OCSP_URL") or "http://127.0.0.1:5000",
        DEFAULT_CA_ISSUER_URL=os.environ.get("DEFAULT_CA_ISSUER_URL") or "http://127.0.0.1:5000",

        DEFAULT_POLICY_URL=os.environ.get("DEFAULT_POLICY_URL") or "http://127.0.0.1:5000/repository",
        DEFAULT_POLICY_OID=os.environ.get("DEFAULT_POLICY_OID") or "1.3.6.1.4.1",
    )

    connect("pki", host=app.config.get("MONGODB_URL"))
    Bootstrap(app)

    @app.route("/")
    def home():
        return redirect("/certificates")

    from pki import certificates, repository, ocsp
    from pki.auth import check_permission

    if app.config.get("WEBAUTH_HEADER"):
        logger.info(f"auth is enabled with {app.config.get('WEBAUTH_HEADER')} header")
        certificates.bp.before_request(check_permission)

    app.register_blueprint(certificates.bp, url_prefix="/certificates")
    app.register_blueprint(repository.bp, url_prefix="/repository")
    app.register_blueprint(ocsp.bp, url_prefix="/ocsp")

    return app
