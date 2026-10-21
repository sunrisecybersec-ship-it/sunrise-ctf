FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --home-dir /app appuser
COPY app.py challenges_level1.json challenges_level2.json setup.py roles.html ./
RUN mkdir -p /data && chown -R appuser:appuser /app /data
USER appuser
EXPOSE 8001 8002
CMD ["python", "app.py"]
