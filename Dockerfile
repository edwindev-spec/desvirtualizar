FROM node:22-bookworm-slim

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends python3 python3-venv git ca-certificates lua5.1 \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m bot
WORKDIR /app

COPY requirements.txt .
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

ARG BRANCH=coderabbit/prometheus-vm-devirtualizer/4fb4f45b
ARG COMMIT=98e1d89faeddbe8d478a9b72df58d13d43a2b765
RUN git clone --single-branch --branch "$BRANCH" https://github.com/edwin-dev67/coderabit.git /app/prometheus-recover \
 && git -C /app/prometheus-recover checkout --detach "$COMMIT" \
 && test "$(git -C /app/prometheus-recover rev-parse HEAD)" = "$COMMIT"

COPY bot.py .
RUN chown -R bot:bot /app
USER bot

ENV DEOBF_RECOVER_DIR=/app/prometheus-recover \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

CMD ["python", "bot.py"]
