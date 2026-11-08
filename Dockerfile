# Builds Airlock, then copies just the program into an empty image. There's no
# shell or package manager in the result, and nothing that could run a file.
#
#   docker build -t airlock .
#   docker run --rm -t --read-only --cap-drop=ALL airlock scan https://github.com/owner/repo

# Pinned to one exact image, so that a change upstream can't change this build.
FROM rust:1.87-alpine@sha256:126df0f2a57e675f9306fe180b833982ffb996e90a92a793bb75253cfeed5475 AS build
RUN apk add --no-cache build-base
WORKDIR /airlock
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /airlock/target/release/airlock /airlock
# The container is gone after the scan, so a saved copy would be lost with it.
ENV AIRLOCK_NO_SAVE=1
USER 65534:65534
ENTRYPOINT ["/airlock"]
