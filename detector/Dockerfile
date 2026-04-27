FROM python:3.11-slim

# Set working directory inside the container
# Every command from here runs inside /app
WORKDIR /app

# Install system dependencies
# iptables is the Linux firewall tool our blocker uses
# We need to install it inside the container because
# the base image doesn't have it by default
RUN apt-get update && apt-get install -y \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first — before the code
# Why? Docker caches each step as a layer
# If we copy requirements first and they haven't changed,
# Docker skips the pip install step on the next build
# This makes rebuilds much faster
COPY requirements.txt .

# Install Python libraries from requirements.txt
# --no-cache-dir means don't store the download cache
# inside the image — keeps the image smaller
RUN pip install --no-cache-dir -r requirements.txt

# Copy all our Python files into the container
COPY . .

# Tell Docker this container will use port 9000
# This is documentation — it doesn't actually open the port
# The port mapping in docker-compose.yml does that
EXPOSE 9000

# The command that runs when the container starts
# python main.py starts our daemon
CMD ["python", "main.py"]
