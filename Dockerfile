FROM eclipse-temurin:17
COPY target/bank.jar bank.jar
CMD [ "java","-jar","bank.jar" ]
