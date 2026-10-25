"""TLS-required SMTP alert delivery."""
from email.message import EmailMessage
import hashlib
import smtplib
import ssl

def validate(config):
    for key in ('host','sender'):
        value=config.get(key,'')
        if not value or any(c in value for c in '\r\n\x00'):raise ValueError('Invalid SMTP '+key)
    if config.get('mode') not in ('starttls','tls'):raise ValueError('SMTP requires TLS or STARTTLS')
    if not 1<=config.get('port',0)<=65535:raise ValueError('Invalid SMTP port')
    recipients=config.get('recipients',[])
    if not recipients or len(recipients)>50 or any('@' not in x or any(c in x for c in '\r\n\x00') for x in recipients):raise ValueError('Invalid recipients')
    return config

def send(config,alert):
    validate(config)
    context=ssl.create_default_context()
    if config.get('ca'):context.load_verify_locations(cadata=config['ca'])
    message=EmailMessage();message['From']=config['sender'];message['To']=', '.join(config['recipients'])
    message['Subject']='Mr Patchy: '+alert.kind
    message['Message-ID']='<'+hashlib.sha256((alert.id+str(alert.created)).encode()).hexdigest()+'@mrpatchy>'
    message.set_content('Server: '+alert.host_id+'\n\n'+alert.message)
    cls=smtplib.SMTP_SSL if config['mode']=='tls' else smtplib.SMTP
    kwargs={'context':context} if config['mode']=='tls' else {}
    with cls(config['host'],config['port'],timeout=15,**kwargs) as smtp:
        if config['mode']=='starttls':smtp.ehlo();smtp.starttls(context=context);smtp.ehlo()
        if config.get('username'):smtp.login(config['username'],config.get('password',''))
        smtp.send_message(message)
