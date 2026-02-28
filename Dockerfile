FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /app

COPY mvnw pom.xml ./
COPY .mvn .mvn
RUN chmod +x mvnw

RUN --mount=type=cache,target=/root/.m2 ./mvnw -B dependency:go-offline

COPY src src
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -DskipTests package

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

RUN useradd -ms /bin/bash gatewayuser

COPY --from=build --chown=gatewayuser:gatewayuser /app/target/api-gateway-*.jar app.jar

USER gatewayuser

ENV JAVA_OPTS="-Xms256m -Xmx512m"

EXPOSE 8081

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]