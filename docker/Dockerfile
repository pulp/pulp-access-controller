FROM python:3.13-slim

# Create non-root user with fixed UID
RUN useradd -u 1001 -r -m -d /app -s /sbin/nologin appuser

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY pulp_oauth2_auth.py .

# Ensure permissions
RUN chown -R 1001:1001 /app

# Switch to non-root by UID
USER 1001

# Run the Kopf operator
CMD ["kopf", "run", "--standalone", "main.py"]
