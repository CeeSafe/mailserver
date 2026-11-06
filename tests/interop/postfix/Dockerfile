# A real Postfix as the remote MX for the relay's interop test (tests/interop/run.sh): mail for any address at
# remote.test goes to one Maildir, /var/mail/vhosts/remote.test/ (Postfix adds Delivered-To); reject* addresses
# get 550; STARTTLS with
# a self-signed certificate.
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix openssl \
    && rm -rf /var/lib/apt/lists/*
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=mx.remote.test" \
        -keyout /etc/ssl/private/mx.key -out /etc/ssl/certs/mx.pem \
    && mkdir -p /var/mail/vhosts && chown -R 5000:5000 /var/mail/vhosts \
    && postconf -e "myhostname = mx.remote.test" "mydestination = localhost" "inet_interfaces = all" \
        "inet_protocols = ipv4" "mynetworks = 127.0.0.0/8" "maillog_file = /dev/stdout" \
        "virtual_mailbox_domains = remote.test" "virtual_mailbox_base = /var/mail/vhosts" \
        "virtual_mailbox_maps = static:remote.test/" "virtual_uid_maps = static:5000" \
        "virtual_gid_maps = static:5000" \
        "smtpd_recipient_restrictions = check_recipient_access regexp:/etc/postfix/reject, permit_mynetworks, reject_unauth_destination" \
        "smtpd_tls_cert_file = /etc/ssl/certs/mx.pem" "smtpd_tls_key_file = /etc/ssl/private/mx.key" \
        "smtpd_tls_security_level = may" "smtpd_tls_received_header = yes" "message_size_limit = 2000000" \
        "smtputf8_enable = yes" \
    && printf '/^reject/ 550 5.1.1 no such user here\n' > /etc/postfix/reject
EXPOSE 25
CMD ["postfix", "start-fg"]
