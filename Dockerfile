FROM openjdk:11.0.11-slim-buster

RUN apt-get update && apt-get -y install libsodium-dev

WORKDIR /workspace