FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
# Keep an explicit revision marker so each application source sync invalidates
# the image layer that copies the web application into the runtime image.
ARG BUILD_REV=2026-08-25-contract-bilingual-lifecycle-v1
RUN echo "Building Khaisha HR revision ${BUILD_REV}"
COPY hr_platform/ /app/
COPY start.sh /app/start.sh

# ReportLab's dependency-free PDF writer needs a real Unicode font for Arabic.
# Install the freely redistributable Noto/DejaVu fonts in the image so
# contracts and certificates render identically on Render and locally.
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-noto-core fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/data \
    && chmod +x /app/start.sh

EXPOSE 8765
CMD ["/app/start.sh"]
