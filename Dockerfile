FROM golang:1.20-alpine

WORKDIR /usr/src/app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o endkey -tags netgo ./cmd/.

EXPOSE 8080
ENTRYPOINT ["./endkey", "api", "--log=stdout", "--debug"]