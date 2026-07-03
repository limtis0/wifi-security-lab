FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iw \
    wireless-tools \
    net-tools \
    iputils-ping \
    tcpdump \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY images/base/lib.sh /usr/local/lib/wifi-lab/lib.sh
RUN chmod +x /usr/local/lib/wifi-lab/lib.sh

RUN useradd -m -s /bin/bash researcher

WORKDIR /opt

ENV TZ=UTC
ENV LANG=C.UTF-8

LABEL org.wifi-security-lab.role="base"
