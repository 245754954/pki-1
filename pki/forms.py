import wtforms
from flask_wtf import FlaskForm


class ConfirmForm(FlaskForm):
    submit = wtforms.SubmitField("确认")


class CreateCertificateForm(FlaskForm):
    c = wtforms.StringField(
        "国家 [C]", default="CN", validators=[wtforms.validators.DataRequired()])

    st = wtforms.StringField(
        "省 [ST]", default="Beijing", validators=[wtforms.validators.DataRequired()])

    l = wtforms.StringField(
        "市 [L] ", default="Chaoyang", validators=[wtforms.validators.DataRequired()])

    o = wtforms.StringField(
        "单位 [O]", default="Example .ltd", validators=[wtforms.validators.DataRequired()])

    ou = wtforms.StringField(
        "部门 [O]", default="IT", validators=[wtforms.validators.DataRequired()])

    cn = wtforms.StringField(
        "通用名称 [CN]", description="网站域名", default="Example Root CA",
        validators=[wtforms.validators.DataRequired()])

    san = wtforms.TextAreaField("主题备用名称 [SAN]", description="IP 或者域名，每行一个")

    duration = wtforms.IntegerField(
        "有效期", default=365, validators=[wtforms.validators.DataRequired()])

    is_ca = wtforms.BooleanField("CA")
    server_auth = wtforms.BooleanField("Server Auth")
    client_auth = wtforms.BooleanField("Client Auth")

    parent = wtforms.StringField("签发证书编号 [SN]", render_kw={'disabled': ''})

    submit = wtforms.SubmitField("申请")
