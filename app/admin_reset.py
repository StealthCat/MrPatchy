"""Local recovery CLI. Requires access to the application's database/volume."""
import argparse
import getpass
import sys
from sqlalchemy import inspect, select, update
from .db import Session, Setting, engine, audit
from .identity import User
from .security import password_hash


def reset(username, password, reset_mfa=False, enable=False):
    if not 12 <= len(password) <= 1024 or '\x00' in password or '\n' in password or '\r' in password:
        raise ValueError('Password must contain 12–1024 characters without line breaks or NUL')
    if not inspect(engine).has_table('users'):
        raise ValueError('No initialized user database found; check DATA_DIR/DATABASE_URL')
    encoded = password_hash(password)
    with Session() as session:
        account = session.get(User, username)
        if not account or account.role != 'admin':
            raise ValueError('An existing administrator username is required; no account was created or promoted')
        values = {'password':encoded,'generation':User.generation+1}
        if enable: values['enabled'] = True
        if reset_mfa: values.update(otp_secret='',otp_pending='',otp_counter=-1)
        changed=session.execute(update(User).where(User.username==username,User.role=='admin').values(**values))
        if changed.rowcount != 1:raise ValueError('Administrator changed concurrently; retry after reviewing the account')
        if username == 'admin': session.merge(Setting(key='admin',value={'hash':encoded}))
        for row in session.scalars(select(Setting).where(Setting.key.like('session:%'))):
            if row.value.get('username') == username: session.delete(row)
        audit(session,'local administrator password reset',username+('; MFA cleared' if reset_mfa else '; MFA preserved')+('; account enabled' if enable else ''))
        session.commit()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username',default='admin')
    parser.add_argument('--reset-mfa',action='store_true',help='Also remove this administrator’s MFA enrollment')
    parser.add_argument('--enable',action='store_true',help='Also re-enable a disabled administrator')
    parser.add_argument('--password-stdin',action='store_true',help='Read one password line from stdin; never pass a password as an argument')
    args = parser.parse_args()
    try:
        if args.password_stdin:
            password = sys.stdin.readline(1027).removesuffix('\n').removesuffix('\r')
        else:
            if not sys.stdin.isatty(): raise ValueError('Use an interactive terminal, or explicitly select --password-stdin')
            password = getpass.getpass('New administrator password: ')
            if password != getpass.getpass('Confirm new password: '): raise ValueError('Passwords do not match')
        from .database_config import runtime_guard
        with runtime_guard():
            reset(args.username,password,args.reset_mfa,args.enable)
    except (ValueError,EOFError,KeyboardInterrupt) as error:
        print(str(error) or 'Password reset cancelled',file=sys.stderr); return 1
    print('Administrator password reset. Existing sessions revoked. '+('MFA removed.' if args.reset_mfa else 'MFA preserved.'))
    return 0


if __name__ == '__main__': raise SystemExit(main())
