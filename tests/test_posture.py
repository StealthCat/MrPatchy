from app import posture

NOW=1_800_000_000.0
GOOD={'permitrootlogin':'prohibit-password','passwordauthentication':'no','permitemptypasswords':'no','pubkeyauthentication':'yes','x11forwarding':'no','maxauthtries':'3'}


def ev(**kw):
    d={'collected_at':NOW-60,'source':'sshd -T','settings':dict(GOOD)}
    d.update(kw);return d


def states(report):return {r['setting']:r['state'] for r in report['results']}


def test_compliant_evidence_passes_every_rule():
    report=posture.evaluate_ssh(ev(),NOW)
    assert report['state']=='pass' and report['counts']['pass']==len(posture.SSH_RULES) and report['version']==posture.RULESET_VERSION


def test_failing_setting_reports_measured_expected_and_remediation():
    report=posture.evaluate_ssh(ev(settings={**GOOD,'permitrootlogin':'YES','maxauthtries':'10'}),NOW)
    assert report['state']=='fail'
    r={x['setting']:x for x in report['results']}
    assert r['permitrootlogin']['state']=='fail' and r['permitrootlogin']['measured']=='yes' and r['permitrootlogin']['remediation']
    assert r['maxauthtries']['state']=='fail' and r['passwordauthentication']['state']=='pass' and r['passwordauthentication']['remediation'] is None


def test_missing_setting_is_unknown_not_compliant():
    settings={k:v for k,v in GOOD.items() if k!='x11forwarding'}
    report=posture.evaluate_ssh(ev(settings=settings),NOW)
    assert states(report)['x11forwarding']=='unknown' and report['state']=='unknown'


def test_unusable_evidence_is_never_compliant():
    for evidence in (None,'x',{},ev(error='permission denied'),ev(collected_at=NOW-90000),ev(collected_at=NOW+10000),ev(collected_at=True),ev(collected_at=float('nan')),ev(settings=[])):
        report=posture.evaluate_ssh(evidence,NOW)
        assert report['state']=='unknown' and report['counts']['pass']==0 and report['collected_at'] is None


def test_not_applicable_when_daemon_absent():
    report=posture.evaluate_ssh({'applicable':False},NOW)
    assert report['state']=='not_applicable' and report['counts']['not_applicable']==len(posture.SSH_RULES)


def test_values_are_bounded_and_non_numeric_limit_fails():
    report=posture.evaluate_ssh(ev(settings={**GOOD,'maxauthtries':'x'*5000}),NOW)
    r={x['setting']:x for x in report['results']}
    assert r['maxauthtries']['state']=='fail' and len(r['maxauthtries']['measured'])<=200
