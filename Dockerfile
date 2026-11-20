FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 echat \
    && useradd --uid 10001 --gid echat --no-create-home echat \
    && mkdir -p /app/data && chown echat:echat /app/data
COPY --chown=echat:echat echat ./echat
COPY --chown=echat:echat web ./web
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=4)"
CMD ["python", "-m", "echat", "serve"]