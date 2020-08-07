import os
from flask import Flask, redirect
from flask_bootstrap import Bootstrap
from mongoengine import connect


def create_app():
    app = Flask(__name__)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or "catfish",
        BOOTSTRAP_SERVE_LOCAL=True,  # 默认会使用 CDN 资源
        MONGODB_URL=os.environ.get("MONGODB_URL") or "mongodb://localhost:27017"
    )

    connect("pki", host=app.config.get("MONGODB_URL"))
    Bootstrap(app)

    @app.route("/")
    def home():
        return redirect("/certificates")

    from pki import certificates
    app.register_blueprint(certificates.bp, url_prefix="/certificates")

    return app
