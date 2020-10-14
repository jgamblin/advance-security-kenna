FROM python:3-alpine

WORKDIR /app

RUN apk add build-base curl-dev libcurl libressl-dev

COPY ghas_kenna ghas_kenna
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

ENTRYPOINT [ "python3", "-m", "ghas_kenna" ]
