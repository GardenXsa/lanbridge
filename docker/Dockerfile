FROM python:3.12-slim

WORKDIR /app

COPY lanbridge/ ./lanbridge/
COPY entry.py .
COPY pyproject.toml .
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Relay server port
EXPOSE 9876/udp

# Run relay server
CMD ["python3", "-c", "import asyncio; from lanbridge.relay import run_relay_server; asyncio.run(run_relay_server('0.0.0.0', 9876))"]
