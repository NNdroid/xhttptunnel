#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${PROJECT_ROOT}/bin"
mkdir -p "${BIN_DIR}"

APP_NAME="xhttptunnel"

# Release versions use v1.0.yyyyMMdd-<short commit hash>. CI passes the tag
# explicitly; local builds derive the same shape from the current UTC date and
# HEAD. Override without editing this script: VERSION=v1.0.20260904-8f60417 ...
if [ -z "${VERSION:-}" ]; then
  BUILD_DATE="$(date -u +%Y%m%d)"
  GIT_HASH="$(git -C "${PROJECT_ROOT}" rev-parse --short=7 HEAD 2>/dev/null || true)"
  if [ -z "${GIT_HASH}" ]; then
    GIT_HASH="unknown"
  fi
  VERSION="v1.0.${BUILD_DATE}-${GIT_HASH}"
fi

LDFLAGS="-s -w -X main.version=${VERSION}"

SUPPORTED_PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "linux/386"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
  "windows/386"
)

# Opt in with --update-deps (or UPDATE_GO_DEPS=1) to run
# "go get -u ./..." and "go mod tidy" before compiling.
UPDATE_GO_DEPS="${UPDATE_GO_DEPS:-0}"
BUILD_ARGS=()
for ARG in "$@"; do
  case "${ARG}" in
    --update-deps|--update-go-deps)
      UPDATE_GO_DEPS=1
      ;;
    *)
      BUILD_ARGS+=("${ARG}")
      ;;
  esac
done

if [ "${#BUILD_ARGS[@]}" -gt 0 ]; then
  PLATFORMS=("${BUILD_ARGS[@]}")
else
  PLATFORMS=("${SUPPORTED_PLATFORMS[@]}")
fi

for PLATFORM in "${PLATFORMS[@]}"; do
  case " ${SUPPORTED_PLATFORMS[*]} " in
    *" ${PLATFORM} "*) ;;
    *)
      echo "Unsupported build target: ${PLATFORM}" >&2
      echo "Supported targets: ${SUPPORTED_PLATFORMS[*]}" >&2
      exit 2
      ;;
  esac
done

case "${UPDATE_GO_DEPS}" in
  1|true|TRUE|yes|YES)
    echo "=== Updating Go dependencies ==="
    (
      cd "${PROJECT_ROOT}"
      go get -u ./...
      go mod tidy
    )
    ;;
  0|false|FALSE|no|NO|"")
    ;;
  *)
    echo "UPDATE_GO_DEPS must be 0/1, true/false, or yes/no; got: ${UPDATE_GO_DEPS}" >&2
    exit 2
    ;;
esac

echo "=== Building ${APP_NAME} ${VERSION} ==="

for PLATFORM in "${PLATFORMS[@]}"; do
  GOOS="${PLATFORM%/*}"
  GOARCH="${PLATFORM#*/}"
  
  OUTPUT="${BIN_DIR}/${APP_NAME}_${GOOS}_${GOARCH}"
  if [ "${GOOS}" == "windows" ]; then
    OUTPUT="${OUTPUT}.exe"
  fi
  
  echo "--> Compiling ${GOOS}/${GOARCH}..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${OUTPUT}" "${PROJECT_ROOT}"
done

echo "=== Build Complete! Artifacts in ${BIN_DIR} ==="
