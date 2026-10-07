# Sentrix backend - cloud mode (LOCAL_CAPTURE=false, no packet sniffing in-container, so no
# Administrator/root/Npcap needed here; traffic comes from remote agents over /agent/v1/*).
FROM python:3.11-slim

WORKDIR /app

# libgomp1: required by xgboost/tensorflow at runtime (not needed for scapy in cloud mode, but
# cheap to keep so the same image also works with LOCAL_CAPTURE=true on a Linux host with
# CAP_NET_RAW granted).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
