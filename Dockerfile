FROM python:3-alpine

COPY entrypoint.py /entrypoint.py
COPY requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

ENTRYPOINT [ "python3", "/entrypoint.py" ]
