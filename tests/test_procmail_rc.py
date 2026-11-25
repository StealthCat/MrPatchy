"""Tests for the pure procmail rcfile execution contract (#1507)."""
from __future__ import annotations

import pytest

from app import procmail_rc as pr


def user(text, **kw):
    return pr.assess_rcfile(text, kind='user', recipient='alice', **kw)


def glob(text, privileged_start=True):
    return pr.assess_rcfile(text, kind='global', recipient='alice', privileged_start=privileged_start)


def kinds(result):
    return [(e['kind'], e['command']) for e in result['executions']]


def test_pipe_action_runs_as_recipient_and_is_guarded():
    result = user(':0\n* ^Subject: run\n| /usr/local/bin/hook --flag\n')
    assert kinds(result) == [('pipe', '/usr/local/bin/hook --flag')]
    entry = result['executions'][0]
    assert entry['run_as'] == 'alice' and entry['guarded'] is True
    assert entry['via_shell'] is False and entry['recipe_line'] == 1
    assert result['complete'] is True and result['origin'] == 'not_assessed'


def test_shell_metacharacters_select_the_shell():
    result = user(':0 c\n|cat > /tmp/x; /bin/y\n')
    assert result['executions'][0]['via_shell'] is True


def test_filter_flag_and_wait_flags_are_reported():
    entry = user(':0 fw\n| formail -A "X-Seen: 1"\n')['executions'][0]
    assert entry['kind'] == 'filter' and entry['flags'] == 'fw'


def test_bare_pipe_writes_to_stdout_without_execution():
    assert user(':0\n|\n')['executions'] == []


def test_condition_programs_including_negated_weighted_and_expanded():
    text = (':0\n* ? /bin/check-a\n* ! ? /bin/check-b\n* -100^0 ? /bin/check-c\n'
            '* $ ? /bin/check-d\n* ^From: x\n/dev/null\n')
    result = user(text)
    assert [c for k, c in kinds(result) if k == 'condition'] == [
        '/bin/check-a', '/bin/check-b', '/bin/check-c', '/bin/check-d']
    assert result['complete'] is True


def test_regex_conditions_with_question_marks_do_not_execute():
    result = user(':0\n* ^Subject:.*why?\n* VAR ?? ^x\nmbox\n')
    assert result['executions'] == []


def test_expanded_condition_starting_with_variable_is_unresolved():
    result = user(':0\n* $ $COND\nmbox\n')
    assert result['complete'] is False
    assert result['gaps'][0]['reason'] == 'expanded_condition_unresolved'


def test_backticks_in_assignment_folder_and_forward():
    text = ('DATE=`date +%F`\n:0\n* ^X: y\n`/bin/pick-folder`\n'
            ':0\n* ^X: z\n! `/bin/who-to`\n')
    result = user(text)
    assert [(e['command'], e['context']) for e in result['executions']] == [
        ('date +%F', 'assignment'), ('/bin/pick-folder', 'folder'), ('/bin/who-to', 'forward')]
    assert result['executions'][0]['guarded'] is False
    assert result['forwards'][0]['arguments'] == '`/bin/who-to`'


def test_backticks_inside_single_quotes_and_escaped_do_not_run():
    result = user("A='`not run`'\nB=\\`no\\`\n")
    assert result['executions'] == []


def test_backticks_inside_double_quotes_run():
    result = user('A="x `/bin/y z` w"\n')
    assert kinds(result) == [('backtick', '/bin/y z')]


def test_unterminated_backtick_is_a_gap():
    result = user('A=`/bin/never\n')
    assert result['complete'] is False
    assert result['gaps'][0]['reason'] == 'unterminated_backtick'


def test_capture_pipe_and_forward():
    result = user(':0 w\n* ^X\nVAL=| /bin/extract\n:0\nCOPY=! someone\n')
    assert result['executions'][0]['kind'] == 'capture'
    assert result['executions'][0]['variable'] == 'VAL'
    assert result['forwards'][0]['capture'] == 'COPY'


def test_trap_runs_at_exit():
    result = user('TRAP="/usr/bin/logger done"\n')
    assert kinds(result) == [('trap', '/usr/bin/logger done')]
    assert result['executions'][0]['guarded'] is False


def test_multiple_assignments_on_a_line_and_trailing_comment():
    result = user('A=1 TRAP=/bin/t # comment\n')
    assert kinds(result) == [('trap', '/bin/t')]


def test_nested_blocks_track_depth_and_close():
    text = ':0\n* ^X\n{\n  :0 c\n  | /bin/inner\n\n  TRAP=/bin/t\n}\n:0\n| /bin/outer\n'
    result = user(text)
    by_cmd = {e['command']: e for e in result['executions']}
    assert by_cmd['/bin/inner']['block_depth'] == 1
    assert by_cmd['/bin/t']['guarded'] is True
    assert by_cmd['/bin/outer']['block_depth'] == 0
    assert result['complete'] is True


def test_one_line_block():
    result = user(':0\n* ^X\n{ TRAP=/bin/t }\n')
    assert kinds(result) == [('trap', '/bin/t')]
    assert result['complete'] is True


def test_unclosed_block_is_a_gap():
    result = user(':0\n{\n:0\n| /bin/x\n')
    assert result['complete'] is False
    assert result['gaps'][-1]['reason'] == 'unclosed_block'


def test_unexpected_closing_brace_warns():
    assert user('}\n')['warnings'][0]['reason'] == 'closing_brace_unexpected'


def test_continuation_lines_join():
    result = user(':0\n* ^X\n| /bin/long \\\n  --arg\n')
    assert result['executions'][0]['command'] == '/bin/long   --arg'
    assert result['executions'][0]['line'] == 3


def test_comments_and_blank_lines_after_a_condition_are_skipped():
    result = user(':0\n* ^X\n# note\n\n| /bin/x\n')
    assert kinds(result) == [('pipe', '/bin/x')]
    assert result['complete'] is True


def test_blank_line_before_first_condition_is_unresolved_without_aAeE():
    result = user(':0\n\n| /bin/x\n')
    assert result['complete'] is False
    assert result['gaps'][0]['reason'] == 'blank_line_before_action'


def test_blank_line_before_action_is_skipped_with_e_flag():
    result = user(':0 E\n# else\n| /bin/x\n')
    assert kinds(result) == [('pipe', '/bin/x')]
    assert result['complete'] is True


def test_missing_action_after_skipped_blank_line():
    result = user(':0\n* ^X\n\n:0\n| /bin/y\n')
    assert result['warnings'][0]['reason'] == 'missing_action'
    assert kinds(result) == [('pipe', '/bin/y')]


def test_includerc_and_switchrc_are_unfollowed_gaps():
    result = user('INCLUDERC=$HOME/.pm/inc.rc\nSWITCHRC=/etc/other.rc\n')
    assert [i['variable'] for i in result['includes']] == ['INCLUDERC', 'SWITCHRC']
    assert result['complete'] is False
    assert {g['reason'] for g in result['gaps']} == {'include_not_followed'}


def test_global_rcfile_runs_as_root_until_dropprivs():
    result = glob('TRAP=/bin/a\n:0\n| /bin/root-pipe\nDROPPRIVS=yes\n:0\n| /bin/user-pipe\n')
    assert [e['run_as'] for e in result['executions']] == ['root', 'root', 'alice']


@pytest.mark.parametrize('value,dropped', [
    ('yes', True), ('on', True), ('1', True), ('a', True), ('true', True), ('"Yes"', True),
    ('no', False), ('off', False), ('0', False), ('o', False), ('maybe', False),
])
def test_dropprivs_follows_renvint(value, dropped):
    result = glob(f'DROPPRIVS={value}\n:0\n| /bin/x\n')
    assert result['executions'][0]['run_as'] == ('alice' if dropped else 'root')


def test_conditional_or_dynamic_dropprivs_makes_run_as_unknown():
    assert glob(':0\n* ^X\n{ DROPPRIVS=yes }\n:0\n| /bin/x\n')['executions'][0]['run_as'] == 'unknown'
    assert glob('DROPPRIVS=$DP\n:0\n| /bin/x\n')['executions'][0]['run_as'] == 'unknown'


def test_global_rcfile_unprivileged_and_unknown_starts():
    assert glob(':0\n| /bin/x\n', privileged_start=False)['executions'][0]['run_as'] == 'alice'
    assert glob(':0\n| /bin/x\n', privileged_start=None)['executions'][0]['run_as'] == 'unknown'


def test_reassigned_shell_makes_via_shell_unknown():
    result = user(':0\n| /bin/a\nSHELLMETAS=\n:0\n| /bin/b\n')
    assert [e['via_shell'] for e in result['executions']] == [False, 'unknown']


def test_legacy_condition_count_is_unresolved():
    result = user(':1\n^X\n| /bin/x\n')
    assert result['complete'] is False
    assert result['gaps'][0]['reason'] == 'legacy_condition_count'


def test_header_flags_and_lockfile():
    result = user(':0 Bc: mylock\n* x\n| /bin/x\n')
    assert result['executions'][0]['flags'] == 'Bc'


def test_incomplete_recipe_at_eof():
    result = user(':0\n* ^X\n')
    assert result['complete'] is False
    assert result['gaps'][0]['reason'] == 'incomplete_recipe'


def test_not_observed_and_too_large_fail_closed():
    assert user(None)['gaps'] == [{'reason': 'not_observed'}]
    big = user('#' * (pr.MAX_TEXT + 1))
    assert big['complete'] is False and big['gaps'][0]['reason'] == 'text_too_large'


def test_invalid_kind_rejected():
    with pytest.raises(ValueError):
        pr.assess_rcfile('', kind='other')


def test_folder_delivery_is_not_an_execution():
    result = user(':0:\n* ^From:.*list\nIN.list/\n')
    assert result['executions'] == [] and result['complete'] is True


def test_dollar_prefix_without_space_expands_literal_text():
    result = user(':0\n* $COND\nmbox\n')
    assert result['complete'] is True and result['executions'] == []
