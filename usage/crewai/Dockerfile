FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the usage package structure
RUN mkdir -p /app/usage/crewai/artifacts /app/usage/crewai/tools && \
    touch /app/usage/__init__.py && \
    touch /app/usage/crewai/__init__.py

# Copy all crewai code into the package directory
COPY . /app/usage/crewai/

# Ensure __init__.py files exist after copy (in case docker-compose context lacks them)
RUN touch /app/usage/__init__.py /app/usage/crewai/__init__.py

# Create config from example if not present
RUN if [ ! -f /app/usage/crewai/config.yaml ]; then \
        cp /app/usage/crewai/config.example.yaml /app/usage/crewai/config.yaml; \
    fi

# Entry point: python -m usage.crewai.crew
ENTRYPOINT ["python", "-m", "usage.crewai.crew"]