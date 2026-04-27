FROM ubuntu:24.04

# Install Python, standard utilities, and bws CLI dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    curl unzip procps net-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Make python3 available as python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install bws CLI
RUN curl -fsSL https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.0.0/bws-x86_64-unknown-linux-gnu-2.0.0.zip \
    -o /tmp/bws.zip && \
    unzip /tmp/bws.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/bws && \
    rm /tmp/bws.zip

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt awscli

COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000 8001 8002

ENTRYPOINT ["/app/entrypoint.sh"]
