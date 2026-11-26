#!/bin/sh
# A mirror may publish its signed release and package indexes at different times.
set -eu

for attempt in 1 2 3; do
    if apt-get update --error-on=any; then
        exit 0
    else
        status=$?
    fi
    if [ "$attempt" -lt 3 ]; then
        delay=$((attempt * 5))
        printf 'APT index refresh attempt %s failed. Retrying in %s seconds.\n' "$attempt" "$delay" >&2
        sleep "$delay"
    fi
done

exit "$status"
