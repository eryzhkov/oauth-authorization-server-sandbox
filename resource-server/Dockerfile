FROM eclipse-temurin:17 AS app-build

ENV APP_BUILD_DIR=/opt/build

WORKDIR ${APP_BUILD_DIR}
COPY ./target/resource-server-*.jar ./rs.jar
RUN java -Djarmode=layertools -jar rs.jar extract

FROM eclipse-temurin:17

ENV APP_BUILD_DIR=/opt/build

RUN groupadd rs \
  && useradd --gid rs --shell /bin/bash --create-home rs
USER rs:rs
WORKDIR /opt/rs

COPY --from=app-build ${APP_BUILD_DIR}/spring-boot-loader/ ./
COPY --from=app-build ${APP_BUILD_DIR}/dependencies/ ./
COPY --from=app-build ${APP_BUILD_DIR}/snapshot-dependencies/ ./
COPY --from=app-build ${APP_BUILD_DIR}/application/ ./

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]