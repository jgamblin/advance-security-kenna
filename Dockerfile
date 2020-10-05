FROM python:3-alpine

COPY entrypoint.py /entrypoint.py

ENTRYPOINT [ "python3", "/entrypoint.py" ]
