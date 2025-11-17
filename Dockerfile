# ====== BUILD STAGE ======
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom first and prefetch dependencies (cache optimization)
COPY pom.xml .
RUN mvn -B -q -DskipTests dependency:go-offline

# Copy sources and build
COPY src ./src
RUN mvn -B clean package -DskipTests

# ====== RUNTIME STAGE ======
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy the fat JAR from the build stage
COPY --from=build /app/target/*.jar app.jar

# Render will inject PORT at runtime (defaults to 10000 if not overridden)
# We'll default to 8080 locally
ENV JAVA_OPTS=""
ENV PORT=8080

# Expose 8080 for local runs; Render doesn't require EXPOSE but it's fine
EXPOSE 8080

# Bind Spring Boot to the PORT env var
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=${PORT} -jar app.jar"]
