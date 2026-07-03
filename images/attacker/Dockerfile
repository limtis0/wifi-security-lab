FROM wifi-lab-base:latest

LABEL org.wifi-security-lab.role="attacker"

# Install aircrack-ng suite
RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng \
    mdk4 \
    && rm -rf /var/lib/apt/lists/*

# Create venv and install Python attack dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
    scapy \
    numpy \
    scipy \
    matplotlib \
    pandas \
    jupyter \
    tqdm

# Install the attacks package
COPY pyproject.toml /opt/pyproject.toml
COPY attacks/ /opt/attacks/
RUN pip install -e /opt/

COPY images/attacker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /opt

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
