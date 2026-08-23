FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY hr_platform/ /app/
COPY start.sh /app/start.sh

RUN mkdir -p /var/data && chmod +x /app/start.sh

EXPOSE 8765
CMD ["/app/start.sh"]
