FROM golang:1 AS build
WORKDIR /usr/src/bowness
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN cd cmd/bowness && ./build.sh

FROM debian:12
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
COPY --from=build /usr/src/bowness/cmd/bowness .
CMD ["./bowness", "config.yaml"]
