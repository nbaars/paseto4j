FROM openjdk:18.0.2-slim-buster

RUN apt-get update && apt-get -y install libsodium-dev

WORKDIR /workspace