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

# Copy crew code (including subpackages)
COPY . .

# Create config from example if not present
RUN if [ ! -f config.yaml ]; then cp config.example.yaml config.yaml; fi

# Entry point
ENTRYPOINT ["python", "-m", "usage.crewai.crew"]
