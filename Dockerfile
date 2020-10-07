FROM python:3-alpine

WORKDIR /app

COPY ghas_kenna ghas_kenna
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

ENTRYPOINT [ "python3", "-m", "ghas_kenna" ]
