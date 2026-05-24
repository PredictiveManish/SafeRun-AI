FROM python:3.11-slim

RUN useradd -m -u 1000 -s /bin/bash sandbox

WORKDIR /sandbox

RUN chown sandbox:sandbox /sandbox && chmod 755 /sandbox

USER sandbox

CMD ["python", "-u", "/sandbox/script.py"]
