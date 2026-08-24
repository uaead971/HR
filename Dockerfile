FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
# Keep an explicit revision marker so each application source sync invalidates
# the image layer that copies the web application into the runtime image.
ARG BUILD_REV=2026-08-24-leave-policy-eos-v2
RUN echo "Building Khaisha HR revision ${BUILD_REV}"
COPY hr_platform/ /app/
COPY start.sh /app/start.sh

RUN mkdir -p /var/data && chmod +x /app/start.sh

EXPOSE 8765
CMD ["/app/start.sh"]
