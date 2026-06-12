# Public python slim base — replaces the retired private p3d3-slim base image.
# gaius-common is consumed as a git-sourced library by the gaius services; this
# image carries no app build steps (matching the previous base-only stub).
ARG PYTHON_VERSION=3.12
ARG DEBIAN_SUITE=bookworm

FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE}
