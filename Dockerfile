FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY . /app/
RUN mkdir -p /var/data && chmod +x /app/start.sh

EXPOSE 8765
CMD ["/app/start.sh"]
