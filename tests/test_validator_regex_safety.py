import random
import re
import time
import pytest
from app.main import key_filename
from target.agent import response_service_units

ORIGINAL_KEY=re.compile(r'[A-Za-z0-9_-]+\.(gpg|asc)')
ORIGINAL_UNIT=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@:\-]*\.service')
ALPHABET='aZ09_-.@:/ \n'


def unit_ok(unit):
    try:response_service_units([unit])
    except ValueError:return False
    return True


def samples(seed,suffixes):
    rng=random.Random(seed)
    for _ in range(20000):
        yield ''.join(rng.choice(ALPHABET) for _ in range(rng.randrange(0,12)))+rng.choice(suffixes)


def test_key_filename_accepts_exactly_the_previous_pattern():
    for name in ['vendor.gpg','a.asc','A-b_9.gpg','x.gpg.asc','.gpg','a.GPG','a.pgp','a.gpg\n','a/b.gpg','-.asc','','gpg','a..gpg']:
        assert key_filename(name)==bool(ORIGINAL_KEY.fullmatch(name)),name
    for name in samples(1,['.gpg','.asc','.gpgx','asc','']):
        assert key_filename(name)==bool(ORIGINAL_KEY.fullmatch(name)),name


def test_service_unit_validator_accepts_exactly_the_previous_pattern():
    for unit in ['ssh.service','getty@tty1.service','a.b:c-d_e.service','.service','-x.service','x.service.service','x.socket','x.service\n','x/y.service','x .service']:
        assert unit_ok(unit)==bool(ORIGINAL_UNIT.fullmatch(unit)),unit
    for unit in samples(2,['.service','.servic','service','']):
        if len(unit)<=128:assert unit_ok(unit)==bool(ORIGINAL_UNIT.fullmatch(unit)),unit


@pytest.mark.parametrize('value',['-'*200_000+'!','0'*200_000+'!','.'*200_000])
def test_validators_reject_long_adversarial_input_quickly(value):
    started=time.monotonic()
    assert not key_filename(value)
    assert not unit_ok(value)
    assert time.monotonic()-started<1


def test_key_upload_rejects_overlong_filename(admin):
    response=admin.put('/api/hosts/missing/keys',json={'name':'a'*252+'.gpg','data':''})
    assert response.status_code==422
