# Multi-stage build for the Lemma Agent binary.
#
# Build:    docker build -t lemma-agent:dev -f agent/Dockerfile agent/
# Run:      docker run --rm lemma-agent:dev version
# K8s:      see agent/deploy/k8s-sidecar.yaml.tmpl
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/lemma-agent .

# Distroless static for a minimal runtime — no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lemma-agent /usr/local/bin/lemma-agent
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/lemma-agent"]
CMD ["serve", "--port=8080", "--evidence-dir=/var/lib/lemma-agent/evidence", "--keys-dir=/var/lib/lemma-agent/keys"]
EXPOSE 8080
