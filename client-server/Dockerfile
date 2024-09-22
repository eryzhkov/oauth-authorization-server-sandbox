FROM eclipse-temurin:17 AS app-build

ENV APP_BUILD_DIR=/opt/build

WORKDIR ${APP_BUILD_DIR}
COPY ./target/client-server-*.jar ./cs.jar
RUN java -Djarmode=layertools -jar cs.jar extract

FROM eclipse-temurin:17

ENV APP_BUILD_DIR=/opt/build

RUN groupadd cs \
  && useradd --gid cs --shell /bin/bash --create-home cs
USER cs:cs
WORKDIR /opt/cs

COPY --from=app-build ${APP_BUILD_DIR}/spring-boot-loader/ ./
COPY --from=app-build ${APP_BUILD_DIR}/dependencies/ ./
COPY --from=app-build ${APP_BUILD_DIR}/snapshot-dependencies/ ./
COPY --from=app-build ${APP_BUILD_DIR}/application/ ./

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]