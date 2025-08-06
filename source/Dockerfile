FROM python:3.14.0rc1-bookworm

RUN mkdir -p /usr/src/app

COPY KeyFragmentDistributor.py /usr/src/app

COPY KeyFragmenter.py /usr/src/app

COPY FileEncrypter.py /usr/src/app

COPY server.py /usr/src/app

COPY requirements.txt /usr/src/app

WORKDIR /usr/src/app

RUN pip install -r requirements.txt

EXPOSE 41398 41399 41400

CMD ["python", "server.py"]