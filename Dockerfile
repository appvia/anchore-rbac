FROM alpine:3.8
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk add --no-cache ca-certificates

ADD bin/authorization-plugin-server /authorization-plugin-server

USER 65535

ENTRYPOINT [ "/authorization-plugin-server" ]
