FROM alpine:latest

RUN mkdir /usr/src/app

COPY KeyFragmentDistributor.py /usr/src/app

COPY KeyFragmenter.py /usr/src/app

COPY FileEncrypter.py /usr/src/app

COPY server.py /usr/src/app

WORKDIR /usr/src/app

RUN pip install -r requirements.txt

CMD ["python", "./s3.py"]