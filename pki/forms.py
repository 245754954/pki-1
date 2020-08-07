import wtforms
from flask_wtf import FlaskForm
from wtforms import Form


class ConfirmForm(FlaskForm):
    submit = wtforms.SubmitField("Confirm")


class AuthorityInformationAccessForm(Form):
    enabled = wtforms.BooleanField("enabled")
    ca_issuers = wtforms.StringField("CA Issueres")
    ocsp = wtforms.StringField("OCSP")


class ModeForm(Form):
    is_ca = wtforms.BooleanField("CA")
    is_server_auth = wtforms.BooleanField("Server Auth")
    is_client_auth = wtforms.BooleanField("Client Auth")


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

    parent = wtforms.StringField("Issuer Serial Number [SN]", render_kw={'disabled': ''})

    mode = wtforms.FormField(ModeForm, label="Mode")

    aia = wtforms.FormField(AuthorityInformationAccessForm, label="Authority Information Access")

    submit = wtforms.SubmitField("Create")
