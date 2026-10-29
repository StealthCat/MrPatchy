#!/bin/sh
# Disposable container fixture only; this is not a real service-manager test.
printf '%s\n' "$*" >> /opt/drpatch/systemctl-test.log
case "$1" in
  is-active) echo active;;
  is-enabled) echo enabled;;
  show)
    case "$*" in
      *--property=Id,*)
        for unit in "$@"; do :; done
        active=active;result=success
        if [ -f /opt/drpatch/service-health-failed ]; then active=failed;result=exit-code; fi
        printf '%s\n' "Id=$unit" 'LoadState=loaded' "ActiveState=$active" 'SubState=running' "Result=$result" 'ExecMainCode=0' 'ExecMainStatus=0' 'MainPID=41' 'NRestarts=0' 'InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "FragmentPath=/etc/systemd/system/$unit" 'UnitFileState=enabled';;
      *) printf '%s\n' 'FragmentPath=/etc/systemd/system/mrpatchy-agent.service' 'DropInPaths=';;
    esac;;
esac
exit 0
