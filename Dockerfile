FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
# Keep an explicit revision marker so each application source sync invalidates
# the image layer that copies the web application into the runtime image.
ARG BUILD_REV=2026-10-08-v58-bilingual-contract-arial-r9
RUN echo "Building Khaisha HR revision ${BUILD_REV}"
COPY hr_platform/ /app/
COPY start.sh /app/start.sh

# The dependency-free PDF writer prefers Arial. Linux uses the freely
# redistributable Arial-compatible Liberation family when it has the required
# glyphs, then the Unicode-complete DejaVu fallback. This prevents bilingual
# contracts from showing square missing-glyph boxes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-liberation2 fonts-noto-core fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/data \
    && chmod +x /app/start.sh

EXPOSE 8765
CMD ["/app/start.sh"]
