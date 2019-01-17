FROM python:3.5-alpine

ENV ROLES_DIR=/opt/work \
    GITHUB_TOKEN= \
    REPO_NAME= \
    PR= \
    PUBLISH=

ADD . /opt/lint/

RUN apk add --no-cache gcc  musl-dev libffi-dev openssl-dev make python3-dev \
&& pip install -r /opt/lint/requirements.txt

WORKDIR /opt/work/

VOLUME /opt/work/

ENTRYPOINT ["python", "/opt/lint/lint3.py"]
CMD ["--version"]
