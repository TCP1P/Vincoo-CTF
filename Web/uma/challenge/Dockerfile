FROM tomcat:9.0.98-jdk11 AS builder

# install maven and gcc
RUN apt-get update && apt-get install -y maven gcc

# Compile readflag.c
COPY readflag.c /tmp/readflag.c
RUN gcc -o /usr/local/bin/readflag /tmp/readflag.c

WORKDIR /tmp/lib
COPY ./lib /tmp/lib
RUN mvn clean compile && mvn clean package

FROM tomcat:9.0.98-jdk11

WORKDIR /usr/local/tomcat

COPY --from=builder /tmp/lib/target/demo-1.0-SNAPSHOT.jar /usr/local/tomcat/lib/demo-1.0-SNAPSHOT.jar
COPY --from=builder /usr/local/bin/readflag /readflag

# add setuid root to readflag
RUN chmod u+s /readflag

COPY ./flag.txt /root/flag.txt
RUN chmod 644 /root/flag.txt

COPY ./conf/web.xml conf/web.xml
COPY ./conf/context.xml conf/context.xml
COPY src webapps/

USER 404
EXPOSE 8080
CMD ["catalina.sh", "run"]
