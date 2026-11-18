import pytest

from app import binfmt_rules as br

ETC, RUN, LOCAL, USR = br.DIRECTORIES
QEMU_ARM = (r':qemu-arm:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00'
            r':\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff'
            r':/usr/libexec/qemu-binfmt/arm-binfmt-P:POCF')


def listed(*entries, complete=True):
    return {'state': 'listed', 'complete': complete, 'entries': list(entries)}


def absent():
    return {'state': 'absent', 'entries': []}


def f(name, content, complete=True):
    return {'name': name, 'type': 'file', 'content': content, 'content_complete': complete}


def dirs(**over):
    base = {ETC: absent(), RUN: absent(), LOCAL: absent(), USR: absent()}
    key = {'etc': ETC, 'run': RUN, 'local': LOCAL, 'usr': USR}
    base.update({key[k]: v for k, v in over.items()})
    return base


def run(**over):
    return br.evaluate(dirs(**over))


def handler_names(result):
    return [h['name'] for h in result['handlers']]


# --- systemd file selection (conf-files.c, flags 0) ---------------------------------------------

def test_no_files_is_complete_and_registers_nothing():
    result = run()
    assert result['complete'] is True
    assert result['handlers'] == [] and result['flushes_existing'] is True


def test_etc_overrides_usr_and_files_apply_in_basename_order():
    result = run(etc=listed(f('b.conf', ':b:E::bb::/bin/b:\n')),
                 usr=listed(f('b.conf', ':evil:E::x::/bin/x:\n'), f('a.conf', ':a:E::aa::/bin/a:\n')))
    assert result['complete'] is True
    # a.conf registers first, b.conf (from /etc) second; the newest handler is consulted first.
    assert handler_names(result) == ['b', 'a']
    usr_b = next(r for r in result['files'] if r['path'] == f'{USR}/b.conf')
    assert usr_b['status'] == 'ignored' and usr_b['reason_code'] == 'overridden'
    assert usr_b['overridden_by'] == f'{ETC}/b.conf'


@pytest.mark.parametrize('entry,code', [
    (f('x.conf', ''), 'masked'),
    ({'name': 'x.conf', 'type': 'symlink', 'link_target': '/dev/null', 'target': {'type': 'other'},
      'content': '', 'content_complete': True}, 'masked'),
    ({'name': 'x.conf', 'type': 'symlink', 'link_target': '/gone', 'target': None}, 'dangling_symlink'),
    ({'name': 'x.conf', 'type': 'directory'}, 'directory'),
])
def test_unstatted_names_still_shadow_lower_directories(entry, code):
    result = run(etc=listed(entry), usr=listed(f('x.conf', ':x:E::x::/bin/x:\n')))
    assert result['complete'] is True
    assert result['handlers'] == []
    top = next(r for r in result['files'] if r['directory'] == ETC)
    assert top['reason_code'] == code and top['status'] == 'no_rules'


@pytest.mark.parametrize('name', ['.x.conf', 'x.conf~', 'x.conf.bak', 'x.conf.dpkg-old', 'x.cnf', 'x.conf.rpmnew'])
def test_hidden_backup_and_wrong_suffix_names_are_not_read(name):
    result = run(etc=listed(f(name, ':x:E::x::/bin/x:\n')))
    assert result['handlers'] == []
    assert result['files'][0]['reason_code'] == 'name_ignored'


def test_backup_suffix_only_applies_after_last_dot():
    # "x.dpkg-old.conf" ends in ".conf", and the text after the last dot is "conf", so it is read.
    assert br.name_considered('x.dpkg-old.conf') is True
    assert br.name_considered('x.bak.conf') is True


# --- line handling (fileio.c read_line + strstrip + COMMENTS) ----------------------------------

def test_comments_blank_lines_whitespace_and_cr_nul_line_ends():
    content = '# c\n; c\n\n  \t:a:E::aa::/bin/a:  \r:b:E::bb::/bin/b:\x00:c:E::cc::/bin/c:'
    result = run(etc=listed(f('x.conf', content)))
    assert handler_names(result) == ['c', 'b', 'a']


# --- systemd rule-name handling and replacement --------------------------------------------------

@pytest.mark.parametrize('rule', [':register:E::x::/bin/x:', ':status:E::x::/bin/x:', '::E::x::/bin/x:',
                                  ':..:E::x::/bin/x:'])
def test_systemd_refuses_reserved_and_invalid_names(rule):
    result = run(etc=listed(f('x.conf', rule)))
    assert result['rules'][0]['status'] == 'name_refused'
    assert result['handlers'] == []


def test_later_rule_with_same_name_replaces_earlier():
    result = run(etc=listed(f('a.conf', ':h:E::one::/bin/one:'), f('b.conf', ':h:E::two::/bin/two:')))
    assert [h['extension'] for h in result['handlers']] == ['two']
    assert result['rules'][0]['status'] == 'replaced'
    assert result['rules'][0]['replaced_by'] == {'file': f'{ETC}/b.conf', 'line': 1}


def test_rejected_later_rule_still_deletes_earlier_handler():
    result = run(etc=listed(f('a.conf', ':h:E::one::/bin/one:\n:h:X::bad::/bin/x:')))
    assert result['handlers'] == []
    assert [r['status'] for r in result['rules']] == ['replaced', 'kernel_rejected']


# --- kernel create_entry -------------------------------------------------------------------------

@pytest.mark.parametrize('rule', [
    ':a:E::x::/b:',             # minimal valid at 12 bytes with newline
    '|n|M|0|\\x7fELF||/i|',     # custom delimiter, explicit zero offset
    ':n:M:+2:ab::/i:',          # kstrtoint accepts a leading '+'
    ':n:M:-0:ab::/i:',          # "-0" parses to zero
    ':n:E:junk:ext:junk:/i:',   # offset and mask fields are skipped for E rules
    ':n:M::\\\\x41::/i:',       # backslash not followed by x is literal
    ':n:M::a\\x41:\\xff\\xff:/i:PPOO',
])
def test_kernel_accepts(rule):
    handler, why = br.kernel_parse(rule)
    assert handler is not None, why


@pytest.mark.parametrize('rule,fragment', [
    (':a:E::x::', '11'),                          # too short
    (':n:Z::x::/i:', 'type'),
    (':n:EE::x::/i:', 'single character'),
    (':n:M:-1:ab::/i:', 'offset'),
    (':n:M:0x1:ab::/i:', 'offset'),
    (':n:M:+-1:ab::/i:', 'offset'),
    (':n:M::\\x4::/i:', 'escape'),
    (':n:M::ab:\\xg0:/i:', 'escape'),
    (':n:M::::/i:', 'magic is empty'),
    (':n:M::ab:\\xff:/i:', 'mask length'),
    (':n:M:255:ab::/i:', 'header'),
    (':n:E::::/i:', 'extension'),
    (':n:E::a/b::/i:', 'extension'),
    (':n:E::x:::', 'interpreter is empty'),
    (':n:E::x::/i:PX', 'flags'),
    (':n:E::x::/i', 'flags'),                   # no closing delimiter: the newline lands in the interpreter
    (':n/x:E::x::/i:', 'name'),
])
def test_kernel_rejects(rule, fragment):
    handler, why = br.kernel_parse(rule)
    assert handler is None
    assert fragment in why


def test_offset_plus_size_boundary():
    assert br.kernel_parse(':n:M:254:ab::/i:')[0] is not None
    assert br.kernel_parse(':n:M:255:ab::/i:')[0] is None


def test_register_length_boundary():
    pad = 'a' * (br.MAX_REGISTER_LENGTH - len(':n:E::x::/:') - 1)
    assert br.kernel_parse(f':n:E::x::/{pad}:')[0] is not None
    assert br.kernel_parse(f':n:E::x::/{pad}a:')[0] is None


def test_qemu_style_rule_fields_and_flags():
    handler, _ = br.kernel_parse(QEMU_ARM)
    assert handler['type'] == 'magic' and handler['offset'] == 0
    assert handler['magic_hex'].startswith('7f454c46') and len(handler['mask_hex']) == len(handler['magic_hex'])
    assert handler['flags'] == 'POCF'
    result = run(usr=listed(f('qemu-arm.conf', QEMU_ARM + '\n')))
    h = result['handlers'][0]
    assert h['conditional'] is True and result['rules'][0]['status'] == 'registered_if_interpreter_opens'
    attrs = h['attributes']
    assert attrs['credentials_from_binary'] and attrs['open_binary'] and attrs['interpreter_opened_at_registration']
    # It matches only 32-bit ARM ELF files, never every ELF header, so it is not a native-ELF interceptor.
    assert attrs['matches_elf_header'] is False


# --- interception attributes ---------------------------------------------------------------------

@pytest.mark.parametrize('rule,elf,shebang,anything', [
    (':n:M::\\x7fELF::/i:', True, False, False),
    (':n:M::\\x7fE::/i:', True, False, False),
    (':n:M:1:ELF::/i:', True, False, False),
    (':n:M::#!::/i:', False, True, False),
    (':n:M::\\x00\\x00:\\x00\\x00:/i:', True, True, True),
    (':n:M::\\x7fELF\\x02:\\xff\\xff\\xff\\xff\\x00:/i:', True, False, False),
    (':n:M::\\x7fELF\\x02::/i:', False, False, False),   # requires the 64-bit class byte, so not every ELF
    (':n:M:4:\\x02::/i:', False, False, False),
    (':n:E::sh::/i:', False, False, False),
])
def test_match_classification(rule, elf, shebang, anything):
    result = run(etc=listed(f('x.conf', rule)))
    attrs = result['handlers'][0]['attributes']
    assert (attrs['matches_elf_header'], attrs['matches_shebang'], attrs['matches_any_content']) == \
        (elf, shebang, anything)


def test_c_flag_implies_open_binary_and_relative_interpreter_is_flagged():
    result = run(etc=listed(f('x.conf', ':n:E::x::relative/i:C')))
    attrs = result['handlers'][0]['attributes']
    assert attrs['credentials_from_binary'] and attrs['open_binary'] and attrs['interpreter_relative']
    assert result['handlers'][0]['conditional'] is False


# --- fail-closed gaps ----------------------------------------------------------------------------

@pytest.mark.parametrize('over,code', [
    ({'etc': None}, 'directory_not_observed'),
    ({'etc': {'state': 'unreadable', 'entries': []}}, 'directory_unreadable'),
    ({'etc': listed(complete=False)}, 'listing_incomplete'),
    ({'etc': {'state': 'listed', 'entries': []}}, 'input_malformed'),
    ({'etc': {'state': 'absent', 'entries': [f('x.conf', '')]}}, 'input_malformed'),
    ({'etc': listed({'name': 'x.conf', 'type': 'file'})}, 'content_not_observed'),
    ({'etc': listed(f('x.conf', ':a:E::x::/b:', complete=False))}, 'content_incomplete'),
    ({'etc': listed(f('x.conf', 'x' * (br.MAX_CONTENT_CHARS + 1)))}, 'content_too_large'),
    ({'etc': listed({'name': 'x.conf', 'type': 'other'})}, 'special_file'),
    ({'etc': listed({'name': 'x.conf', 'type': 'symlink'})}, 'metadata_missing'),
    ({'etc': listed(f('x.conf', ''), f('x.conf', ''))}, 'duplicate_name'),
    ({'etc': listed({'name': 'a/b', 'type': 'file'})}, 'input_malformed'),
])
def test_blocking_gaps(over, code):
    d = dirs()
    key = {'etc': ETC}
    for k, v in over.items():
        if v is None:
            d.pop(key[k])
        else:
            d[key[k]] = v
    result = br.evaluate(d)
    assert code in {g['code'] for g in result['gaps']}
    assert result['complete'] is False


def test_unresolved_top_file_does_not_fall_back_to_lower_copy():
    result = run(etc=listed({'name': 'x.conf', 'type': 'file'}), usr=listed(f('x.conf', ':x:E::x::/bin/x:')))
    assert result['handlers'] == [] and result['complete'] is False
    top = next(r for r in result['files'] if r['directory'] == ETC)
    assert top['status'] == 'unresolved'


def test_non_mapping_input_fails_closed():
    result = br.evaluate(None)
    assert result['complete'] is False
    assert result['handlers'] == []


def test_gap_budget_is_bounded():
    entries = [{'name': f'{i}.conf', 'type': 'file'} for i in range(200)]
    result = run(etc=listed(*entries))
    assert len(result['gaps']) == br.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'


def test_rule_budget_is_bounded():
    content = '\n'.join(f':h{i}:E::e{i}::/i:' for i in range(br.MAX_RULES + 5))
    result = run(etc=listed(f('x.conf', content)))
    assert len(result['rules']) == br.MAX_RULES
    assert 'too_many_rules' in {g['code'] for g in result['gaps']} and result['complete'] is False


def test_result_never_authorizes_action():
    result = run(etc=listed(f('x.conf', ':n:M::\\x7fELF::/tmp/i:C')))
    assert result['origin'] == 'not_assessed'
    assert 'not a safety verdict' in result['note']
    assert not any(k in result for k in ('action', 'authorized', 'response'))
