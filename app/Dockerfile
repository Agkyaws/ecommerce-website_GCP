# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Get the PORT from the environment (Cloud Run injects this)
ENV PORT 8080

# Use Gunicorn as the production web server
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app