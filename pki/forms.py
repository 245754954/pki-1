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


class PolicyForm(Form):
    oid = wtforms.StringField("OID")
    url = wtforms.StringField("URL")


class CRLDistributionPointsForm(Form):
    url = wtforms.StringField("URL")


class ImportCertificateForm(FlaskForm):
    certificate = wtforms.TextAreaField(
        "Certificate", description="PEM Format", validators=[wtforms.validators.DataRequired()])
    private_key = wtforms.TextAreaField(
        "Private Key", description="PEM Format")
    password = wtforms.PasswordField("Private Key Password", description="Keep empty if no password")
    submit = wtforms.SubmitField("Import")


class UploadCertificateForm(FlaskForm):
    certificate = wtforms.FileField()
    submit = wtforms.SubmitField("Import")


class ScanCertificateForm(FlaskForm):
    url = wtforms.StringField("URL", default="https://www.apple.com")
    submit = wtforms.SubmitField("Scan")


class CreateCertificateForm(FlaskForm):
    COUNTRY_NAME = wtforms.StringField("Country [C]")

    STATE_OR_PROVINCE_NAME = wtforms.StringField("State [ST]")

    LOCALITY_NAME = wtforms.StringField("Locality [L] ")

    ORGANIZATION_NAME = wtforms.StringField("Organization [O]")

    ORGANIZATIONAL_UNIT_NAME = wtforms.StringField("Organization Unit [OU]")

    COMMON_NAME = wtforms.StringField("Common Name [CN]", validators=[wtforms.validators.DataRequired()])

    EMAIL_ADDRESS = wtforms.StringField("Email [E]")

    san = wtforms.TextAreaField("Subject Alternative Name [SAN]", description="IP or domain, one item each line")

    duration = wtforms.IntegerField("Duration", description="Days", validators=[wtforms.validators.DataRequired()])

    parent = wtforms.StringField("Issuer Serial Number [SN]", render_kw={'disabled': ''})

    mode = wtforms.FormField(ModeForm, label="Mode")

    policy = wtforms.FormField(PolicyForm, label="Policy")

    crl = wtforms.FormField(CRLDistributionPointsForm, label="Certificate Revocation List")

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
