FROM python:3-alpine

RUN adduser -D vulnx

WORKDIR /vulnx

COPY . /vulnx

RUN chown -R vulnx:vulnx /vulnx && \
    pip install -r ./requirements.txt

USER vulnx

ENTRYPOINT [ "python", "vulnx.py" ]

CMD ["--help"]
