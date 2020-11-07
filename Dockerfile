FROM python:3.9.0-buster

## Updating The Image To Fix Found Vulns
RUN apt update -y && apt upgrade -y

COPY entrypoint.py /entrypoint.py
COPY requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

ENTRYPOINT [ "python3", "/entrypoint.py" ]
