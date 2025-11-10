# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
# (app.py, index.html, and the 'static' folder)
COPY . .

# Get the PORT from the environment (Cloud Run injects this)
ENV PORT 8080

# Use Gunicorn as the production web server
# This runs your 'app.py' file (app:app)
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "app:app"]