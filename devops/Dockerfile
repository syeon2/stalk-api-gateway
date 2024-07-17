FROM openjdk:17.0.2-slim

COPY ./build/libs/*.jar ./stalkApiGateway.jar

ARG ENCRYPT_PASSWORD

ENV ENCRYPT_PASSWORD=$ENCRYPT_PASSWORD

ENTRYPOINT ["java", "-jar", "./stalkApiGateway.jar"]
