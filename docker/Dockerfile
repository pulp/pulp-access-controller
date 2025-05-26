FROM python:3.10-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your controller code
COPY main.py .

# Run the Kopf operator
CMD ["kopf", "run", "--standalone", "main.py"]
