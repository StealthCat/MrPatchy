"""Disposable MySQL connection probe. Exchange credentials via stdin and a category via stdout."""

import json
import ssl
import sys

import pymysql


def classify(error):
    code = error.args[0] if error.args and isinstance(error.args[0], int) else None
    text = str(error).lower()
    if code in (1045, 1698):
        return 'authentication'
    if code == 1049:
        return 'database'
    if code in (1044, 1142, 1227):
        return 'access'
    if isinstance(error, ssl.SSLError) or 'ssl' in text or 'certificate' in text or 'tls' in text:
        return 'tls'
    if isinstance(error, TimeoutError) or 'timed out' in text:
        return 'timeout'
    if code in (2003, 2005, 2002, 2006, 2013) or isinstance(error, OSError):
        return 'connectivity'
    return 'error'


def probe(kwargs):
    connection = None
    try:
        connection = pymysql.connect(**kwargs)
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
    except Exception as error:
        return classify(error)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    return 'ok'


if __name__ == '__main__':
    print(probe(json.load(sys.stdin)))
