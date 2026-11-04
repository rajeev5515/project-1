#!/bin/sh
# Volumes (Fly, Render, docker -v) are mounted root-owned at runtime, which
# hides the chown done at build time. Fix ownership, then drop to the
# unprivileged "node" user before starting the app.
set -e
mkdir -p "${TV_DATA_DIR:-/data}"
if [ "$(id -u)" = "0" ]; then
  chown -R node:node "${TV_DATA_DIR:-/data}"
  chmod 700 "${TV_DATA_DIR:-/data}"
  if command -v setpriv >/dev/null 2>&1; then
    exec setpriv --reuid=node --regid=node --init-groups "$@"
  fi
  echo '{"type":"warning","message":"setpriv not found; running as root"}'
fi
exec "$@"
