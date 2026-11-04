FROM python:3.12-slim

# tzdata: "kemarin" dan batas hari dihitung dari TZ; harus sama dengan zona waktu log server
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analisis_harian.py .

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

USER 10001
ENTRYPOINT ["python", "analisis_harian.py"]
