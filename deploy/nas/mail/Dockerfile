FROM alpine:3.22

RUN apk add --no-cache ca-certificates opendkim postfix && \
    install -d -m 0755 /run/opendkim /etc/opendkim

COPY entrypoint.sh /usr/local/sbin/clustr-mail-entrypoint
COPY healthcheck.sh /usr/local/sbin/clustr-mail-healthcheck
COPY opendkim.conf /etc/opendkim/opendkim.conf

RUN chmod 0555 /usr/local/sbin/clustr-mail-entrypoint /usr/local/sbin/clustr-mail-healthcheck

EXPOSE 25
HEALTHCHECK --interval=10s --timeout=5s --retries=12 \
  CMD ["/usr/local/sbin/clustr-mail-healthcheck"]

ENTRYPOINT ["/usr/local/sbin/clustr-mail-entrypoint"]
