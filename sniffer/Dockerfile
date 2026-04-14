FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    libpq-dev \
    libpcap-dev \
    tcpdump \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 5000

CMD ["/app/entrypoint.sh"]
