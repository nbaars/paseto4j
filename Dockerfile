FROM eclipse-temurin:11.0.16.1_1-jre-focal


RUN apt-get update && apt-get -y install libsodium-dev

WORKDIR /workspace