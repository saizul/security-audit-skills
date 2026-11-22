ARG BASE=python:3.12-slim
FROM golang:1.23 AS builder
WORKDIR /src
COPY go.mod ./
RUN go build -o /out/app .

FROM builder AS test
RUN go test ./...

FROM ${BASE}
COPY --from=builder /out/app /app
USER 10001:10001
CMD ["/app"]
