FROM golang:1.23.1-alpine AS builder

WORKDIR /app

COPY src/go.mod src/go.sum ./
RUN go mod download
COPY src/ .
RUN go build -o main .

FROM scratch
LABEL authors="Valentin Billa"

WORKDIR /root/

COPY --from=builder /app/main .
COPY resources/templates ./resources/templates
COPY resources/assets ./resources/assets

COPY config.yml .
CMD ["./main"]