#!/bin/sh
set -eu
: "${ANALYST_API_UPSTREAM:?Set the reachable analyst API origin}"
: "${ANALYST_API_TLS_NAME:=analyst-api}"
: "${ANALYST_API_CA_FILE:=/etc/ssl/certs/ca-certificates.crt}"
printf '%s' "$ANALYST_API_UPSTREAM" | grep -Eq '^https?://([A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$' || { echo 'Invalid analyst API origin' >&2; exit 1; }
printf '%s' "$ANALYST_API_TLS_NAME" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9.:-]*$' || { echo 'Invalid API TLS name' >&2; exit 1; }
printf '%s' "$ANALYST_API_CA_FILE" | grep -Eq '^/[A-Za-z0-9/_.-]+$' || { echo 'Invalid API CA path' >&2; exit 1; }
test -f "$ANALYST_API_CA_FILE" || { echo 'API CA file not found' >&2; exit 1; }
export ANALYST_API_UPSTREAM ANALYST_API_TLS_NAME ANALYST_API_CA_FILE
envsubst '${ANALYST_API_UPSTREAM} ${ANALYST_API_TLS_NAME} ${ANALYST_API_CA_FILE}' < /etc/cybertriage/nginx.conf.template > /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
