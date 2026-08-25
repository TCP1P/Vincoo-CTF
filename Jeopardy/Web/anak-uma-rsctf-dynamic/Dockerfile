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

# RSCTF dynamic-flag compatibility layer. The build-time scan records
# exact marker-bearing files; runtime replacement is therefore bounded
# to those files instead of walking the image on every team start.
USER root
COPY rsctf-entrypoint.sh /usr/local/bin/rsctf-entrypoint
RUN set -eu; \
    chmod 0555 /usr/local/bin/rsctf-entrypoint; \
    : > /etc/rsctf-flag-targets; \
    for root in /usr/local/tomcat/webapps /usr/local/tomcat/conf/context.xml /usr/local/tomcat/conf/web.xml /root/flag.txt /readflag /usr/local/tomcat/lib/demo-1.0-SNAPSHOT.jar /tmp/lib /tmp/readflag.c /usr/local/tomcat /app /src /srv /home /opt /var/www /challenge /chall /ctf /root /usr/src /usr/local/bin /workspace /flag /flag.txt; do \
      if [ -e "$root" ]; then \
        find "$root" -xdev -type f ! -path /usr/local/bin/rsctf-entrypoint -exec grep -lF -e RSCTF_DYNAMIC_FLAG_afd0a06b189e41e7ba02956b91c0d916edfcd4eeea0a5803cd4e48b97a4f6b72 -e RSCTF_DYNAMIC_FLAG_560075e31559287cb5da7e9450dd96cc6ae02777c8d7578b17bf8 {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
      fi; \
    done; \
    find / -xdev -maxdepth 1 -type f -exec grep -lF -e RSCTF_DYNAMIC_FLAG_afd0a06b189e41e7ba02956b91c0d916edfcd4eeea0a5803cd4e48b97a4f6b72 -e RSCTF_DYNAMIC_FLAG_560075e31559287cb5da7e9450dd96cc6ae02777c8d7578b17bf8 {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
    sort -u /etc/rsctf-flag-targets > /etc/rsctf-flag-targets.sorted; \
    mv /etc/rsctf-flag-targets.sorted /etc/rsctf-flag-targets; \
    while IFS= read -r target; do \
      [ -f "$target" ] || continue; \
      chmod a+w "$target"; \
      parent=$(dirname "$target"); \
      while [ "$parent" != / ]; do chmod a+x "$parent"; parent=$(dirname "$parent"); done; \
    done < /etc/rsctf-flag-targets
USER 404
ENTRYPOINT ["/usr/local/bin/rsctf-entrypoint"]
