FROM alpine:3.22

RUN apk add --no-cache coreutils openssl

COPY bootstrap.sh /usr/local/sbin/clustr-bootstrap

ENTRYPOINT ["/bin/sh", "/usr/local/sbin/clustr-bootstrap"]
