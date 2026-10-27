FROM python:3.12-slim
WORKDIR /app
COPY commander/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 autoip
COPY commander /app/commander
USER autoip
EXPOSE 8080
CMD ["uvicorn", "commander.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
