# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/detenforce detenforce_financial_proxy.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/detenforce /app/detenforce
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app/detenforce"]
