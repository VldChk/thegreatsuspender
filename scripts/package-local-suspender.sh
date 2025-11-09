#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EXT_DIR="${ROOT_DIR}/local-suspender"
DIST_DIR="${ROOT_DIR}/dist"

if [[ ! -d "${EXT_DIR}" ]]; then
  echo "Extension source directory not found: ${EXT_DIR}" >&2
  exit 1
fi

VERSION=$(node -e "process.stdout.write(require(process.argv[1]).version || '')" "${EXT_DIR}/manifest.json")
if [[ -z "${VERSION}" ]]; then
  echo "Unable to read version from manifest.json" >&2
  exit 1
fi

ARCHIVE_NAME="local-suspender-${VERSION}.zip"
mkdir -p "${DIST_DIR}"
ARCHIVE_PATH="${DIST_DIR}/${ARCHIVE_NAME}"

rm -f "${ARCHIVE_PATH}"

pushd "${EXT_DIR}" >/dev/null
zip -r "${ARCHIVE_PATH}" . -x '*/.DS_Store'
popd >/dev/null

echo "Created ${ARCHIVE_PATH}" 
