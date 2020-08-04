import wtforms
from flask_wtf import FlaskForm


class CreateCertificateForm(FlaskForm):
    c = wtforms.StringField(
        "国家", description="[C] - Country ", default="CN", validators=[wtforms.validators.DataRequired()])

    st = wtforms.StringField(
        "省", description="[ST] - State", default="Beijing", validators=[wtforms.validators.DataRequired()])

    l = wtforms.StringField(
        "市", description="[L] - Locality", default="Chaoyang", validators=[wtforms.validators.DataRequired()])

    o = wtforms.StringField(
        "单位", description="[O] - Organization", default="Testin .ltd", validators=[wtforms.validators.DataRequired()])

    ou = wtforms.StringField(
        "部门", description="[O] - Organization Unit", default="IT", validators=[wtforms.validators.DataRequired()])

    cn = wtforms.StringField(
        "通用名称", description="[CN] - Common Name", default="Testin Root CA",
        validators=[wtforms.validators.DataRequired()])

    duration = wtforms.IntegerField(
        "有效期", default=365, validators=[wtforms.validators.DataRequired()])

    is_ca = wtforms.BooleanField("CA")
    server_auth = wtforms.BooleanField("Server Auth")
    client_auth = wtforms.BooleanField("Client Auth")

    san = wtforms.TextAreaField("主题备用名称", description="[SAN] - Subject Alternative Name")

    parent = wtforms.StringField("签发证书", description="Issuer", render_kw={'disabled': ''})

    submit = wtforms.SubmitField("申请")
