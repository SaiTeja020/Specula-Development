FROM scratch
ADD runtime-rootfs.tar /
COPY app /app
USER 10001:10001
WORKDIR /app
ENV PATH=/usr/local/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp TMPDIR=/tmp SPECULA_AUTH_POLICY_PATH=/app/preflight/viewer_policy.json
ENTRYPOINT ["/usr/local/bin/python", "-B", "-u", "/app/preflight/runner.py"]
