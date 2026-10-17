FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY src/AuditWorker.java .
RUN javac AuditWorker.java
EXPOSE 8092
CMD ["java", "AuditWorker"]
