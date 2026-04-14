FROM python:3.14-alpine

ENV VENV_PATH=/opt/venv
RUN python3 -m venv "$VENV_PATH"
ENV PATH="$VENV_PATH/bin:$PATH"

WORKDIR /app
COPY ./backup_sync_s3 .
COPY run_backup_sync.py .
COPY requirements.txt .

RUN pip install --upgrade pip && pip install -r requirements.txt

ENV PYTHONPATH="/app"

ENTRYPOINT ["python3", "run_backup_sync.py"]