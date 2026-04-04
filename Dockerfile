FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .
COPY mcp_server.py .

EXPOSE 4023
EXPOSE 4444

CMD ["python3", "mcp_server.py"]
