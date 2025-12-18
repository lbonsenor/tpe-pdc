FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Solo instala lo necesario para compilar y correr el proyecto
RUN apt-get update && \
    apt-get install -y gcc make build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /root

# Exponer puertos necesarios para la app (ajusta si es necesario)
EXPOSE 1080
EXPOSE 8080

CMD ["/bin/bash"]