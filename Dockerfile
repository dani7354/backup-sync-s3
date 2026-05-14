FROM python:3.14-alpine

ENV USER=s3sync
ENV GROUPNAME=$USER
ENV UID=2222
ENV GID=3333

RUN addgroup --gid "$GID" "$GROUPNAME" && \
    adduser \
    --disabled-password \
    --gecos "" \
    --ingroup "$GROUPNAME" \
    --no-create-home \
    --uid "$UID" \
    "$USER"


ENV VENV_PATH=/opt/venv
RUN python3 -m venv $VENV_PATH
ENV PATH="$VENV_PATH/bin:$PATH"

RUN chown -R root:root "$VENV_PATH" && chmod -R 755 "$VENV_PATH"

WORKDIR /app
COPY ./backup_sync_s3 ./backup_sync_s3
COPY run_backup_sync.py .
COPY requirements.txt .

RUN pip install --upgrade pip && pip install -r requirements.txt

ENV PYTHONPATH="/app"
RUN chown -R root:root "$PYTHONPATH" && chmod -R 755 "$PYTHONPATH"

USER $UID:$GID

ENTRYPOINT ["python3", "/app/run_backup_sync.py"]