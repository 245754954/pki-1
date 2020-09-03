import os
from flask import Flask, redirect
from flask_bootstrap import Bootstrap
from mongoengine import connect


def create_app():
    app = Flask(__name__)

    app.config.from_mapping(
        BOOTSTRAP_SERVE_LOCAL=True,
        SECRET_KEY=os.environ.get("SECRET_KEY") or "catfish",
        MONGODB_URL=os.environ.get("MONGODB_URL") or "mongodb://localhost:27017",

        DEFAULT_DURATION=os.environ.get("DEFAULT_DURATION") or "365",
        DEFAULT_OCSP_URL=os.environ.get("DEFAULT_OCSP_URL") or "http://ocsp.example.com",
        DEFAULT_CA_ISSUER_URL=os.environ.get("DEFAULT_CA_ISSUER_URL") or "https://pki.example.com"
    )

    connect("pki", host=app.config.get("MONGODB_URL"))
    Bootstrap(app)

    @app.route("/")
    def home():
        return redirect("/certificates")

    from pki import certificates
    app.register_blueprint(certificates.bp, url_prefix="/certificates")

    from pki import ocsp
    app.register_blueprint(ocsp.bp, url_prefix="/ocsp")

    return app
