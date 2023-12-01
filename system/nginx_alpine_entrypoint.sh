#!/usr/bin/env sh
apk add nginx nginx-mod-http-nchan
exec "$@"
