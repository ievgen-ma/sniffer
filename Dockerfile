FROM golang:alpine
RUN apk update
RUN apk add gcc libc-dev libpcap-dev curl
RUN cd /go/bin \
    && curl https://glide.sh/get | sh \
    && apk del curl
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o main .
RUN go build -o main .
CMD ["./main"]