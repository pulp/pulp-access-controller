FROM python:3.15-slim

# Create non-root user with fixed UID
RUN useradd -u 1001 -r -m -d /app -s /sbin/nologin appuser

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies as root first
COPY requirements.txt .
# /cachi2/cachi2.env is only present during hermetic Konflux builds; it points
# pip at the prefetched wheels instead of the network.
RUN if [ -f /cachi2/cachi2.env ]; then . /cachi2/cachi2.env; fi && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py domain_naming.py .

# Ensure all files have correct permissions and ownership
RUN chown -R 1001:1001 /app && \
    chmod -R 755 /app && \
    chmod 644 /app/*.py /app/requirements.txt

# Switch to non-root by UID
USER 1001

# Run the Kopf operator
CMD ["kopf", "run", "--standalone", "main.py"]
