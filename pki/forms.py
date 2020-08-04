import wtforms
from flask_wtf import FlaskForm


class ConfirmForm(FlaskForm):
    submit = wtforms.SubmitField("Confirm")


class CreateCertificateForm(FlaskForm):
    c = wtforms.StringField(
        "Country [C]", default="CN", validators=[wtforms.validators.DataRequired()])

    st = wtforms.StringField(
        "State [ST]", default="Beijing", validators=[wtforms.validators.DataRequired()])

    l = wtforms.StringField(
        "Locality [L] ", default="Chaoyang", validators=[wtforms.validators.DataRequired()])

    o = wtforms.StringField(
        "Organization [O]", default="Example .ltd", validators=[wtforms.validators.DataRequired()])

    ou = wtforms.StringField(
        "Organization Unit [OU]", default="IT", validators=[wtforms.validators.DataRequired()])

    cn = wtforms.StringField(
        "Common Name [CN]", default="Example Root CA",
        validators=[wtforms.validators.DataRequired()])

    san = wtforms.TextAreaField("Subject Alternative Name [SAN]", description="IP or domain, one item each line")

    duration = wtforms.IntegerField(
        "Duration", default=365, validators=[wtforms.validators.DataRequired()])

    is_ca = wtforms.BooleanField("CA")
    server_auth = wtforms.BooleanField("Server Auth")
    client_auth = wtforms.BooleanField("Client Auth")

    parent = wtforms.StringField("Issuer Serial Number [SN]", render_kw={'disabled': ''})

    submit = wtforms.SubmitField("Create")
