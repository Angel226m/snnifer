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

EXPOSE 5000

# Script para iniciar sniffer + Flask app
RUN echo '#!/bin/bash\nset -e\npython -m app &\nwait' > /app/start.sh && chmod +x /app/start.sh

CMD ["python", "-u", "app.py"]
