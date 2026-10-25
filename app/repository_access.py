"""Declarative central APT access; never import executable target APT hooks."""
import re
from urllib.parse import urlsplit
from cryptography import x509

def validate(value):
    if set(value)-{'credentials','proxy','ca','default_release','mirrors'}: raise ValueError('Unknown repository access field')
    credentials=value.get('credentials',[])
    if not isinstance(credentials,list) or len(credentials)>50: raise ValueError('At most 50 repository credentials')
    for item in credentials:
        if set(item)!={'machine','login','password'}: raise ValueError('Credentials require machine, login and password')
        for key,text in item.items():
            if not isinstance(text,str) or not text or len(text)>2000 or re.search(r'[\s\x00-\x1f"\\]',text): raise ValueError('Credential fields cannot contain whitespace, quotes or controls')
        # Require HTTPS scope, including optional path, to avoid sending passwords to HTTP.
        uri=urlsplit(item['machine'])
        if uri.scheme!='https' or not uri.hostname or uri.username or uri.password or uri.query or uri.fragment:
            raise ValueError('Credential machine must be an HTTPS URL, optionally scoped to a path')
    proxy=value.get('proxy','')
    if proxy:
        uri=urlsplit(proxy)
        if uri.scheme not in ('http','https') or not uri.hostname or uri.username or uri.password or re.search(r'[\s"\\\x00-\x1f]',proxy):
            raise ValueError('Proxy must be an HTTP(S) URL without embedded credentials')
    ca=value.get('ca','')
    if ca: x509.load_pem_x509_certificates(ca.encode())
    release=value.get('default_release','')
    if release and not re.fullmatch(r'[A-Za-z0-9_.+*-]{1,120}',release): raise ValueError('Invalid default release')
    mirrors=value.get('mirrors',{})
    if not isinstance(mirrors,dict) or len(mirrors)>50: raise ValueError('At most 50 mirror mappings')
    for source,destination in mirrors.items():
        if not isinstance(source,str) or not source.startswith(('file:','cdrom:','http:','https:')) or any(c in source for c in '\r\n\x00"\\'):
            raise ValueError('Invalid original repository URI')
        uri=urlsplit(destination)
        if uri.scheme not in ('http','https') or not uri.hostname or uri.username or uri.password or re.search(r'[\s"\\\x00-\x1f]',destination):
            raise ValueError('Mirror destination must be an HTTP(S) repository URL')
    return value

def rewrite(content, access):
    for source,destination in sorted(access.get('mirrors',{}).items(),key=lambda item:len(item[0]),reverse=True):
        # URI boundaries avoid remapping a prefix of another repository hostname/path.
        content=re.sub(r'(?<!\S)'+re.escape(source)+r'(?=\s|$)',lambda _:destination,content)
    return content
