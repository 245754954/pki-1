FROM python:3.7.5

WORKDIR /pki
COPY requirements.txt .
RUN pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
COPY . .

VOLUME /data

EXPOSE 5000

ENV FLASK_APP=pki \
    FLASK_ENV=production \
    FLASK_DEBUG=0 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python"]

CMD ["-m","flask","run","--host","0.0.0.0"]