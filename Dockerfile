# --- PRODUCTION DOCKERFILE: Advanced IDS ---
# Use a lightweight but feature-complete Python base
FROM python:3.13-slim

# Set environment variables for non-interactive installs and performance
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install native security and packet-processing dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the dependency manifest first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Ensure necessary directories exist with proper permissions
RUN mkdir -p instance assets/models data/training logs

# Expose the SOC dashboard port
EXPOSE 5001

# The sniffer requires net_raw capabilities. In k8s/Docker, this is handled 
# at the runtime level (cap_add: [NET_ADMIN, NET_RAW]).
CMD ["python", "app.py"]
