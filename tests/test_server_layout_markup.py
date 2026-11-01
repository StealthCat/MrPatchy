import re
from pathlib import Path

SERVER = (Path(__file__).resolve().parents[1] / 'app/static/server.js').read_text()


def test_security_scan_forms_render_inside_cards():
    for form_id in ('security-scan-form', 'yara-scan-form', 'security-policy-form'):
        assert f'<section class="card"><form id="{form_id}">' in SERVER, form_id
    assert SERVER.count('</form></section><section class="card"><form id=') >= 2


def test_pager_buttons_are_grouped_in_actions():
    pagers = ('startup', 'vault', 'archive', 'response', 'process',
              'repair-preparation', 'repair-stage', 'publication')
    for pager in pagers:
        assert f'<div class="actions"><button id="{pager}-prev"' in SERVER, pager
        assert re.search(rf'<button id="{pager}-refresh">[^<]*</button></div>', SERVER), pager


def test_incident_and_startup_buttons_are_grouped():
    assert '<div class="actions"><button data-preserve-incident=' in SERVER
    assert 'Generate AI response plan</button></div>' in SERVER
    heading = SERVER.index('<h3>Reviewed startup baseline')
    assert heading < SERVER.index('id="browse-startup-files"')
