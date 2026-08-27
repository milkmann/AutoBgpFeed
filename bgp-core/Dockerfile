FROM alpine:3.20

RUN apk add --no-cache bird bash curl iproute2

RUN mkdir -p /etc /generated /data/last-good /run/bird

COPY bird.conf /etc/bird.conf

EXPOSE 179

CMD ["bird", "-f", "-c", "/etc/bird.conf"]
