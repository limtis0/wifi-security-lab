FROM wifi-lab-builder:latest AS builder

WORKDIR /tmp/hostap/hostapd

RUN cp defconfig .config && \
    echo "CONFIG_SAE=y" >> .config && \
    echo "CONFIG_IEEE80211W=y" >> .config && \
    echo "CONFIG_ECC=y" >> .config && \
    echo "CONFIG_DRIVER_NL80211=y" >> .config && \
    echo "CONFIG_LIBNL32=y" >> .config && \
    echo "CONFIG_WPS=n" >> .config

RUN make -j"$(nproc)"

FROM wifi-lab-base:latest

LABEL org.wifi-security-lab.role="ap"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnl-3-200 \
    libnl-genl-3-200 \
    dnsmasq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/hostap/hostapd/hostapd /usr/local/bin/hostapd
COPY --from=builder /tmp/hostap/hostapd/hostapd_cli /usr/local/bin/hostapd_cli
RUN --mount=from=builder,src=/lib/,dst=/builder-lib \
    cp /builder-lib/*/libssl.so.1.0.0 /builder-lib/*/libcrypto.so.1.0.0 /usr/lib/ && \
    ldconfig

WORKDIR /opt

COPY images/ap/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
