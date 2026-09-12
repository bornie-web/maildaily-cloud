FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY core.py app.py run.py translation.py netease.py aisummary.py ./
RUN useradd --uid 10001 --create-home maildaily && mkdir /data && chown maildaily /data
USER maildaily
ENV DATABASE_PATH=/data/maildaily.sqlite3
EXPOSE 8000
CMD ["sh","-c","uvicorn run:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --no-access-log"]
