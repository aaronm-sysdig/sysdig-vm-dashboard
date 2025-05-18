FROM python:3.12-slim

WORKDIR /app

COPY app.py download_sysdig_reports.py requirements.txt /app/
RUN python3 -m pip install -r requirements.txt --no-cache-dir
RUN mkdir /app/reports && chown -R 1000:1000 /app/reports

USER 1000

ENTRYPOINT ["python3", "app.py"]