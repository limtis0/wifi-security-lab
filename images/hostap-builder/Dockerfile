FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    pkg-config \
    libnl-3-dev \
    libnl-genl-3-dev \
    libssl-dev \
    libdbus-1-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone vulnerable hostap (hostap_2_4, Dec 2015) — genuinely vulnerable to timing
# side-channel: k=4 constant-time iterations only, no qr/qnr blinding
RUN git clone --branch hostap_2_4 --depth 1 \
    https://git.w1.fi/hostap.git /tmp/hostap

# Apply timing delay patch: configurable usleep per iteration (default 50ms, override via SAE_ITERATION_DELAY_US)
COPY images/hostap-builder/patches/ /tmp/patches/
RUN cd /tmp/hostap && git apply /tmp/patches/timing_delay.patch
