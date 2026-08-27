#!/bin/sh
# Specula dashboard entrypoint: render the nginx config with the gateway API key
# injected server-side, then let nginx start. Requires SPECULA_API_KEY to be set.

if [ -z "${SPECULA_API_KEY:-}" ]; then
    echo "FATAL: SPECULA_API_KEY is required for the dashboard proxy." >&2
    exit 1
fi

export SPECULA_API_KEY
envsubst '${SPECULA_API_KEY}' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf
