# Disposable OpenSSH server for Jato's integration tests. Never expose it beyond localhost.
# The host keys the package installs are removed, so each container makes its own at start
# (`ssh-keygen -A`) and no two containers share a host key.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server sudo \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd \
    && useradd --create-home --shell /bin/sh jato \
    && echo 'jato:jato-test-password' | chpasswd \
    && install -d -m 700 -o jato -g jato /home/jato/.ssh \
    && echo 'jato ALL=(ALL) ALL' > /etc/sudoers.d/jato \
    && chmod 440 /etc/sudoers.d/jato

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22
CMD ["/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
