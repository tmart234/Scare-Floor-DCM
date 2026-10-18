# ER Portable X-ray modality SCP (Scare Floor DCM, stages 1-2)
# Build context MUST be the repo root so shared/ is available:
#   docker build -f challenge/xray-scp/Dockerfile -t scare-floor/xray-scp .
FROM python:3.12-slim

WORKDIR /app

COPY challenge/xray-scp/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY challenge/xray-scp/xray_scp.py /app/xray_scp.py
COPY shared/ /app/shared/

# Flag values are injected at deploy time (k8s Secret), never baked in.
#   FLAG1_AE_TITLE  - accepted called AE title (stage 1 flag, <= 16 chars)
#   FLAG2_PRIVATE   - private-tag value         (stage 2 flag, BHV{...})
ENV XRAY_BIND=0.0.0.0 \
    XRAY_PORT=11112 \
    SCENARIO_PATH=/app/shared/scenario.yaml

EXPOSE 11112

# Drop privileges; the SCP needs no root (port 11112 is unprivileged).
RUN useradd --no-create-home --uid 10001 scare && chown -R scare /app
USER scare

ENTRYPOINT ["python", "/app/xray_scp.py"]
