FROM wifi-lab-builder:latest AS builder

WORKDIR /tmp/hostap/wpa_supplicant

RUN cp defconfig .config && \
    echo "CONFIG_SAE=y" >> .config && \
    echo "CONFIG_IEEE80211W=y" >> .config && \
    echo "CONFIG_ECC=y" >> .config && \
    echo "CONFIG_DRIVER_NL80211=y" >> .config && \
    echo "CONFIG_LIBNL32=y" >> .config

RUN make -j"$(nproc)"

FROM wifi-lab-base:latest

LABEL org.wifi-security-lab.role="client"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnl-3-200 \
    libnl-genl-3-200 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/hostap/wpa_supplicant/wpa_supplicant /usr/local/bin/wpa_supplicant
COPY --from=builder /tmp/hostap/wpa_supplicant/wpa_cli /usr/local/bin/wpa_cli
RUN --mount=from=builder,src=/lib/,dst=/builder-lib \
    cp /builder-lib/*/libssl.so.1.0.0 /builder-lib/*/libcrypto.so.1.0.0 /usr/lib/ && \
    ldconfig

WORKDIR /opt

COPY images/client/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
