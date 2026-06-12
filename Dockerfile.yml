FROM python:3.11-slim

# Installeer de benodigde systeem-pakketten voor Scapy en Postgres
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Kopieer het script naar de container
COPY scanner.py .

# Installeer de Python libraries (Scapy voor netwerk, Psycopg2 voor je database)
RUN pip install --no-cache-dir scapy psycopg2-binary

# Start het script direct op
CMD ["python", "-u", "scanner.py"]
