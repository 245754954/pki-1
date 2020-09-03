import wtforms
import email_validator
from flask_wtf import FlaskForm
from wtforms import Form


class ConfirmForm(FlaskForm):
    submit = wtforms.SubmitField("Confirm")


class AuthorityInformationAccessForm(Form):
    enabled = wtforms.BooleanField("enabled")
    ca_issuers = wtforms.StringField(
        "CA Issueres", description="Must be a valid url", validators=[wtforms.validators.URL()])
    ocsp = wtforms.StringField(
        "OCSP", description="Must be a valid url", validators=[wtforms.validators.URL()])


class ModeForm(Form):
    is_ca = wtforms.BooleanField("CA")
    is_server_auth = wtforms.BooleanField("Server Auth")
    is_client_auth = wtforms.BooleanField("Client Auth")


class ImportCertificateForm(FlaskForm):
    certificate = wtforms.TextAreaField(
        "Certificate", description="PEM Format", validators=[wtforms.validators.DataRequired()])
    private_key = wtforms.TextAreaField(
        "Private Key", description="PEM Format", validators=[wtforms.validators.DataRequired()])
    password = wtforms.PasswordField("Private Key Password", description="Keep empty if no password")
    submit = wtforms.SubmitField("Import")


class CreateCertificateForm(FlaskForm):
    c = wtforms.StringField(
        "Country [C]", validators=[wtforms.validators.DataRequired()])

    st = wtforms.StringField(
        "State [ST]", validators=[wtforms.validators.DataRequired()])

    l = wtforms.StringField(
        "Locality [L] ", validators=[wtforms.validators.DataRequired()])

    o = wtforms.StringField(
        "Organization [O]", validators=[wtforms.validators.DataRequired()])

    ou = wtforms.StringField(
        "Organization Unit [OU]", validators=[wtforms.validators.DataRequired()])

    cn = wtforms.StringField(
        "Common Name [CN]", validators=[wtforms.validators.DataRequired()])

    email = wtforms.StringField("Email [E]", validators=[])

    san = wtforms.TextAreaField("Subject Alternative Name [SAN]", description="IP or domain, one item each line")

    duration = wtforms.IntegerField("Duration", description="Days", validators=[wtforms.validators.DataRequired()])

    parent = wtforms.StringField("Issuer Serial Number [SN]", render_kw={'disabled': ''})

    mode = wtforms.FormField(ModeForm, label="Mode")

    aia = wtforms.FormField(AuthorityInformationAccessForm, label="Authority Information Access")

    submit = wtforms.SubmitField("Create")

    def validate_email(self, field):
        """
        validate email if any
        :param field:
        :return:
        """
        if field.data:
            email_validator.validate_email(
                field.data,
                check_deliverability=True,
            )
