"""Shared helper for tests that save expanding AI admission/spend controls (#881)."""
from app.ai_control_preview import FIELDS


def confirmed_put(client, path, body):
    """Preview the controls in ``body`` and resend the save with the returned confirmation.

    This is what Settings → AI does after an administrator confirms the listed expansions.
    """
    controls = {key: body[key] for key in FIELDS if key in body}
    confirmation = client.post('/api/settings/ai/preview', json=controls).json()['expansion_confirmation']
    return client.put(path, json=body | ({'confirm_ai_expansion': confirmation} if confirmation else {}))
