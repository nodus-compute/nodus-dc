FROM nvidia/cuda:12.4.1-devel-ubuntu22.04@sha256:5645fec64549cc35930eee9d85aafd2b0006c0c3f22632be5a1d85e2604e9749 AS build
COPY probe/probe.c /src/probe.c
RUN gcc -O2 -Wall -Werror -o /nodus-probe /src/probe.c -I/usr/local/cuda/include \
      -L/usr/local/cuda/lib64/stubs -lcuda

# CUDA headers and the link-time stub stay in the builder. The host supplies libcuda through CDI.
# Debian retains ldconfig for the NVIDIA CDI hook and its own package copyright notices.
FROM debian:12-slim@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018
LABEL org.opencontainers.image.source="https://github.com/nodus-compute/nodus-dc" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="Nodus CUDA readiness probe"
COPY --from=build --chmod=0555 /nodus-probe /usr/local/bin/nodus-probe
COPY LICENSE /usr/share/licenses/nodus-probe/LICENSE
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/nodus-probe"]
