"""Shared tracked advisory generation; callers retain policy and evidence gates."""
import json
from . import ai, ai_runs


_PROVIDER_FAILURES = {
    ai.MODEL_REFUSAL: (
        'The model refused to generate an advisory plan. No advisory plan was accepted. '
        'The request was sent and may be billed. Review the incident manually or select a different model.'
    ),
    ai.TOKEN_BUDGET: (
        'The model exhausted the response token budget before completing the advisory plan. '
        'No advisory plan was accepted. The request was sent and may be billed. '
        'Review the incident manually or select a model that can complete within the plan budget.'
    ),
}


def _request(payload, key):
    try:
        return ai.request(payload, key)
    except ai.AIError as error:
        message = _PROVIDER_FAILURES.get(error.cause)
        if message is None or error.transient or error.policy_wait:
            raise
        raise ai.AIError(message, retry_after=error.retry_after, cause=error.cause) from None


def generate(*, model, host_id, subject, schema_name, instructions, evidence,
             schema, secret, validate, persist):
    run_id = None
    try:
        with ai_runs.track('security_plan', model, host_id=host_id, subject=subject) as run_id:
            content = _request({'model': model, 'store': False, 'max_output_tokens': 4000,
                'instructions': instructions, 'input': json.dumps(evidence),
                'text': {'format': {'type': 'json_schema', 'name': schema_name,
                    'strict': True, 'schema': schema}}}, secret())
            validate(content)
            return persist(content, run_id)
    except ai.AIError as error:
        eligible = ai.defer_until(error)
        if eligible is not None:
            ai_runs.defer(run_id, eligible)
        raise
