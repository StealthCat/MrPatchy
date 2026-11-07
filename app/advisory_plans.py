"""Shared tracked advisory generation; callers retain policy and evidence gates."""
import json
from . import ai, ai_runs


def generate(*, model, host_id, subject, schema_name, instructions, evidence,
             schema, secret, validate, persist):
    run_id = None
    try:
        with ai_runs.track('security_plan', model, host_id=host_id, subject=subject) as run_id:
            content = ai.request({'model': model, 'store': False, 'max_output_tokens': 4000,
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
