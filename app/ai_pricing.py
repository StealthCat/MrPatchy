"""Versioned public token-price estimates, never an invoice or a model-access list.

Rates checked 2026-10-26 against https://developers.openai.com/api/docs/pricing
and the individual /api/docs/models/{model} pages for the older models below.
Only exact catalogued IDs are priced: never guess a fine-tune/snapshot's rate.
"""
from decimal import Decimal
import re

VERSION = '2026-10-26'
SOURCE = 'https://developers.openai.com/api/docs/pricing'
# USD per million: ordinary input, cached input, output, 30-minute cache write.
RATES = {
    'gpt-6-astra': ('10', '1', '50', '12.5'),
    'gpt-6.1-sol': ('2', '0.1', '10', '2.5'),
    'gpt-6.1-terra': ('1', '0.05', '5', '1.25'),
    'gpt-6-luna': ('0.1', '0.01', '0.5', '0.125'),
    'gpt-4.1': ('2', '0.5', '8', None),
    'gpt-4.1-mini': ('0.4', '0.1', '1.6', None),
    'gpt-4o-mini': ('0.15', '0.075', '0.6', None),
    'gpt-5-mini': ('0.25', '0.025', '2', None),
}
ALIASES = {
    'gpt-4.1-2025-04-14': 'gpt-4.1',
    'gpt-4.1-mini-2025-04-14': 'gpt-4.1-mini',
    'gpt-4o-mini-2024-07-18': 'gpt-4o-mini',
    'gpt-5-mini-2025-08-07': 'gpt-5-mini',
}
TOKEN_FIELDS = ('input_tokens', 'cached_tokens', 'cache_write_tokens', 'output_tokens', 'reasoning_tokens')


def identifier(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}', value) else ''


def counter(value):
    return type(value) is int and 0 <= value <= 1_000_000_000


def usage_details(data):
    """Keep only bounded token counters; reject inconsistent/malformed usage."""
    usage = data.get('usage')
    if not isinstance(usage, dict): return {}
    inputs, outputs = usage.get('input_tokens'), usage.get('output_tokens')
    details, output_details = usage.get('input_tokens_details', {}), usage.get('output_tokens_details', {})
    if not isinstance(details, dict) or not isinstance(output_details, dict): return {}
    cached, writes, reasoning = details.get('cached_tokens'), details.get('cache_write_tokens', 0), output_details.get('reasoning_tokens')
    if not all(counter(v) for v in (inputs, outputs, writes)): return {}
    if cached is not None and not counter(cached): return {}
    if reasoning is not None and (not counter(reasoning) or reasoning > outputs): return {}
    if (cached or 0) + writes > inputs: return {}
    if 'total_tokens' in usage and (not counter(usage['total_tokens']) or usage['total_tokens'] != inputs + outputs): return {}
    return dict(zip(TOKEN_FIELDS, (inputs, cached, writes, outputs, reasoning)))


def estimate(data, payload):
    """Snapshot observed usage and applicable rates before output validation.

    Output tokens already include reasoning: never charge reasoning twice.
    Missing model/tier/cache information must not be mistaken for zero cost.
    """
    result = {'response_model': identifier(data.get('model')), 'service_tier': '',
              'usage': usage_details(data), 'pricing': {}, 'status': 'unavailable',
              'reason': 'OpenAI did not return valid token usage.'}
    tier = data.get('service_tier')
    if tier in ('default', 'flex', 'priority', 'fast', 'scale', 'ultrafast'):
        result['service_tier'] = tier
    usage = result['usage']
    if not usage: return result
    model = ALIASES.get(result['response_model'], result['response_model'])
    if model not in RATES:
        result['reason'] = 'The returned model has no verified price in this version of Mr Patchy.'
        return result
    rates = RATES[model]
    modern = rates[3] is not None
    if modern and 'cache_write_tokens' not in data['usage'].get('input_tokens_details', {}):
        result['reason'] = 'Cache-write usage was not returned; a reliable estimate is unavailable.'
        return result
    # Old model priority/Flex prices are not inferred from modern multipliers.
    multiplier = {'default': '1'}
    if modern: multiplier.update(flex='0.5', priority='2', fast='2')
    if model in ('gpt-6-astra', 'gpt-6.1-sol'): multiplier['ultrafast'] = '6'
    if result['service_tier'] not in multiplier:
        result['reason'] = 'The processing tier is missing or has no verified price.'
        return result
    if usage['cached_tokens'] is None:
        result['reason'] = 'Cached-input usage was not returned; a reliable estimate is unavailable.'
        return result
    if modern and usage['input_tokens'] > 272000:
        result['reason'] = 'Long-context pricing is not included in this price catalog.'
        return result
    if payload.get('tools'):
        result['reason'] = 'Tool fees are not included in this token-price estimate.'
        return result
    options = payload.get('prompt_cache_options') or {}
    ttl = options.get('ttl', '30m') if isinstance(options, dict) else ''
    if usage['cache_write_tokens'] and (not modern or ttl not in ('30m', '12h')):
        result['reason'] = 'Cache-write pricing is unavailable for this request.'
        return result
    factor = Decimal(multiplier[result['service_tier']])
    prices = [Decimal(v) * factor if v is not None else Decimal(0) for v in rates]
    if ttl == '12h': prices[3] *= 2
    ordinary = usage['input_tokens'] - usage['cached_tokens'] - usage['cache_write_tokens']
    cost = (ordinary * prices[0] + usage['cached_tokens'] * prices[1]
            + usage['output_tokens'] * prices[2] + usage['cache_write_tokens'] * prices[3]) / Decimal(1_000_000)
    result.update(status='estimated', reason='Public token-rate estimate; actual billing may differ.', pricing={
        'estimated_usd': format(cost, 'f'), 'currency': 'USD', 'version': VERSION, 'source': SOURCE,
        'model': model, 'service_tier': result['service_tier'],
        'per_million': dict(zip(('input', 'cached_input', 'output', 'cache_write'), (format(v, 'f') for v in prices))),
        'cache_ttl': ttl if modern else None,
    })
    return result
