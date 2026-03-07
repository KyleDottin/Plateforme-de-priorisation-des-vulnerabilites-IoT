FROM python:3.11-slim

ENV DEBIAN_FRONTEND noninteractive
WORKDIR /app

# install supervisor & cron
RUN \
  apt-get update && \
  apt-get -y upgrade && \
  apt-get install -y \
  supervisor && rm -rf /var/lib/apt/lists/*

# Install python dependencies
RUN pip install --no-cache-dir pandas streamlit

# copy supervisor base configuration and child tasks
COPY supervisord.conf /etc/supervisor/supervisord.conf

# copy other necessary resources/scripts
COPY . /app/

EXPOSE 80

# default command
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
