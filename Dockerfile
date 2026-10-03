# Sandbox image for model-written commands. Same tool set as the benchmark harness's image.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    ripgrep tree findutils coreutils gawk sed grep file \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
CMD ["sleep", "infinity"]
