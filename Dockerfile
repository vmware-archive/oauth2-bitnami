FROM golang:1.12 as builder
COPY . /go/src/github.com/kubeapps/oauth2-bitnami
WORKDIR /go/src/github.com/kubeapps/oauth2-bitnami
RUN CGO_ENABLED=0 go build -a -installsuffix cgo

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/github.com/kubeapps/oauth2-bitnami/oauth2-bitnami /oauth2-bitnami
EXPOSE 8080
CMD ["/oauth2-bitnami"]
