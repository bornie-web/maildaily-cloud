FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY core.py app.py run.py translation.py ./
RUN useradd --uid 10001 --create-home maildaily && mkdir /data && chown maildaily /data
USER maildaily
ENV DATABASE_PATH=/data/maildaily.sqlite3
EXPOSE 8000
CMD ["uvicorn","run:app","--host","0.0.0.0","--port","8000","--workers","1","--no-access-log"]
