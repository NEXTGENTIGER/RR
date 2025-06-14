FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    yara \
    exiftool \
    sleuthkit \
    libmagic1 \
    python3-dev \
    libyara-dev \
    git \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir \
    requests \
    python-magic \
    yara-python \
    git+https://github.com/graingert/python-clamd.git@master \
    distorm3 \
    pycrypto \
    pefile \
    capstone \
    volatility3

COPY forensic_analyzer.py .
COPY rules/malware.yar /app/rules/

RUN mkdir -p /app/logs /app/output /app/input /app/rules && \
    mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 0.0.0.0" >> /etc/clamav/clamd.conf && \
    echo "LocalSocket /var/run/clamav/clamd.sock" >> /etc/clamav/clamd.conf && \
    freshclam || echo "Freshclam failed" && \
    chown -R clamav:clamav /var/lib/clamav && \
    apt-get clean && rm -rf /tmp/* /var/tmp/*

ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

CMD ["sh", "-c", "freshclam && service clamav-daemon start && sleep 5 && python forensic_analyzer.py /app/input"]
