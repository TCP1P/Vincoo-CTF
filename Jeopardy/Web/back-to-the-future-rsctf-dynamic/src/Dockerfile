FROM golang:alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o server main.go

FROM alpine
WORKDIR /app

RUN apk add --no-cache git

COPY --from=builder /app/server /app/server
COPY run.sh /run.sh

RUN chmod +x /run.sh

EXPOSE 80

ENTRYPOINT ["/run.sh"]
