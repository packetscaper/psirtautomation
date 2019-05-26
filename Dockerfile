FROM python:2.7-slim

WORKDIR /psirt

ADD . /psirt

RUN pip install -r requirements.txt

CMD ["python","psirts.py"]

