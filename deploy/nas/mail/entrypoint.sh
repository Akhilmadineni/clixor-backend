#!/bin/sh
set -eu
umask 077

mail_hostname="${CLUSTER_MAIL_HOSTNAME:-mail.atlanteanz.com}"
mail_domain="${CLUSTER_MAIL_DOMAIN:-atlanteanz.com}"
dkim_selector="${CLUSTER_DKIM_SELECTOR:-clixor}"
source_key=/run/secrets/dkim.private

if [ ! -s "$source_key" ]; then
  echo "Missing DKIM private key" >&2
  exit 1
fi

install -d -m 0750 -o opendkim -g opendkim /run/opendkim
install -m 0400 -o opendkim -g opendkim "$source_key" /run/opendkim/dkim.private
printf '%s._domainkey.%s %s:%s:/run/opendkim/dkim.private\n' \
  "$dkim_selector" "$mail_domain" "$mail_domain" "$dkim_selector" \
  > /etc/opendkim/KeyTable
printf '*@%s %s._domainkey.%s\n' "$mail_domain" "$dkim_selector" "$mail_domain" \
  > /etc/opendkim/SigningTable
printf '127.0.0.1\n172.31.253.0/29\n' > /etc/opendkim/TrustedHosts

postconf -e "myhostname = $mail_hostname"
postconf -e "mydomain = $mail_domain"
postconf -e 'myorigin = $mydomain'
postconf -e 'mydestination = localhost.$mydomain, localhost'
postconf -e 'relayhost ='
postconf -e 'relay_domains ='
postconf -e 'inet_interfaces = all'
postconf -e 'inet_protocols = ipv4'
postconf -e 'mynetworks = 127.0.0.0/8, 172.31.253.0/29'
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, reject'
postconf -e 'smtpd_client_restrictions = permit_mynetworks, reject'
postconf -e 'disable_vrfy_command = yes'
postconf -e 'smtpd_helo_required = yes'
postconf -e 'strict_rfc821_envelopes = yes'
postconf -e 'smtp_tls_security_level = may'
postconf -e 'smtp_tls_CApath = /etc/ssl/certs'
postconf -e 'smtp_tls_loglevel = 1'
postconf -e 'smtpd_tls_security_level = none'
postconf -e 'message_size_limit = 1048576'
postconf -e 'mailbox_size_limit = 0'
postconf -e 'maximal_queue_lifetime = 1d'
postconf -e 'bounce_queue_lifetime = 1d'
postconf -e 'minimal_backoff_time = 300s'
postconf -e 'maximal_backoff_time = 3600s'
postconf -e 'queue_run_delay = 300s'
postconf -e 'maillog_file = /dev/stdout'
postconf -e 'local_transport = error:local delivery is disabled'
postconf -e 'smtpd_milters = inet:127.0.0.1:8891'
postconf -e 'non_smtpd_milters = inet:127.0.0.1:8891'
postconf -e 'milter_default_action = tempfail'
postconf -e 'milter_protocol = 6'

postfix check
opendkim -f -x /etc/opendkim/opendkim.conf &
opendkim_pid=$!
sleep 1
if ! kill -0 "$opendkim_pid" 2>/dev/null; then
  echo "OpenDKIM did not start" >&2
  exit 1
fi
exec postfix start-fg
