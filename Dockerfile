# Build
FROM golang:alpine AS build

RUN apk add --update git make build-base bash && \
    rm -rf /var/cache/apk/*

WORKDIR /go/src/github.com/wakeful/pve_exporter
COPY . /go/src/github.com/wakeful/pve_exporter
RUN ./build.sh

# Runtime
FROM scratch

COPY --from=build /go/src/github.com/wakeful/pve_exporter/release/pve_exporter-linux-amd64 /pve_exporter

EXPOSE 9090/tcp

ENTRYPOINT ["/pve_exporter"]
CMD ["-h"]
