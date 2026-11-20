FROM alpine:3.20

RUN apk add --no-cache bird

RUN mkdir -p /etc/bird/generated /run/bird

COPY bird.conf.template /etc/bird/bird.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 179

ENTRYPOINT ["/entrypoint.sh"]
