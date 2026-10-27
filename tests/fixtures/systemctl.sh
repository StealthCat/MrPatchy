#!/bin/sh
# Disposable container fixture only; this is not a real service-manager test.
printf '%s\n' "$*" >> /opt/drpatch/systemctl-test.log
case "$1" in
  is-active) echo active;;
  is-enabled) echo enabled;;
  show) printf '%s\n' 'FragmentPath=/etc/systemd/system/mrpatchy-agent.service' 'DropInPaths=';;
esac
exit 0
