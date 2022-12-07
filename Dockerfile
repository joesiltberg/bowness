FROM golang:1.19 AS build
WORKDIR /usr/src/bowness
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build -v /usr/src/bowness/cmd/bowness

FROM debian:11
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
COPY --from=0 /usr/src/bowness/bowness .
CMD ["./bowness", "config.yaml"]
