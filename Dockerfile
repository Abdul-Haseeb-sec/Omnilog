FROM python:3.11-slim

RUN useradd -m -u 1000 user

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure run_prod.sh is executable
RUN chmod +x run_prod.sh

# Create persistent storage files/directories and set ownership
RUN touch threat_intel.json && mkdir -p reports && chown -R user:user /app

USER user

EXPOSE 5000

# Run the production script using Gunicorn
CMD ["./run_prod.sh"]
