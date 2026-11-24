"""Versioned public token-price estimates, never an invoice or a model-access list.

Rates checked 2026-11-16 against https://developers.openai.com/api/docs/pricing
and the individual /api/docs/models/{model} pages for the older models below.
Only exact catalogued IDs are priced: never guess a fine-tune/snapshot's rate.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from decimal import Decimal
from decimal import ROUND_CEILING
import hashlib
import json
import re
import time

VERSION = '2026-11-16'
SOURCE = 'https://developers.openai.com/api/docs/pricing'
# Bundled catalogs are deliberately short-lived: an old build must not silently
# promise a spend cap using rates that have not been reverified. An
# administrator can reverify the same rates in Settings (#1487); the newer of
# the bundled and administrator-confirmed catalogs applies, and both expire.
VERIFIED_AT = 1794787200  # 2026-11-16T00:00:00Z
EXPIRES_AT = 1797379200   # 2026-12-16T00:00:00Z
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
RATE_FIELDS = ('input', 'cached_input', 'output', 'cache_write')
STORED_KEY = 'ai_price_catalog'
MAX_CONFIRMATION_DAYS = 30
ADMIN_VERSION = re.compile(r'admin-[0-9]{8}T[0-9]{6}Z')
RATE_TEXT = re.compile(r'(?:0|[1-9][0-9]{0,4})(?:\.[0-9]{1,6})?')
MAX_RATE = Decimal('10000')
TOKEN_FIELDS = ('input_tokens', 'cached_tokens', 'cache_write_tokens', 'output_tokens', 'reasoning_tokens')
CAP_MODES = ('daily_cap', 'rate_and_daily')


def bundled_catalog():
    """The catalog shipped in this build. Read at call time so a test can pin its window."""
    return {'version': VERSION, 'source': SOURCE, 'verified_at': VERIFIED_AT, 'expires_at': EXPIRES_AT,
            'origin': 'bundled', 'confirmed_by': '', 'rates': RATES}


def normalized_rate(value):
    """Return a canonical positive USD-per-million rate string, or raise ValueError."""
    if not isinstance(value, str) or not RATE_TEXT.fullmatch(value.strip()):
        raise ValueError('Enter each rate as a USD amount per million tokens with at most 6 decimal places.')
    amount = Decimal(value.strip())
    if not 0 < amount <= MAX_RATE:
        raise ValueError('Each rate must be greater than 0 and at most 10000 USD per million tokens.')
    text = format(amount.normalize(), 'f')
    return text


def normalized_rates(entry, bundled):
    """Validate one model's confirmed rates against the bundled rate structure.

    Rates the bundled catalog does not price (an old model's cache write) must
    stay unpriced, so tier multipliers and the modern/legacy distinction remain
    defined by reviewed source.
    """
    if not isinstance(entry, (list, tuple)) or len(entry) != len(RATE_FIELDS):
        raise ValueError('Provide every rate for each catalogued model.')
    values = []
    for value, reference in zip(entry, bundled):
        if reference is None:
            if value is not None:raise ValueError('This model has no verified cache-write price to confirm.')
            values.append(None)
        else:
            values.append(normalized_rate(value))
    return tuple(values)


def stored_catalog(value):
    """Validate a stored administrator-confirmed catalog; return None when unusable.

    Only bundled model IDs are kept. A model whose confirmed rates are missing
    or no longer match the bundled structure stays unpriced (fail closed)
    until an administrator confirms it again.
    """
    if not isinstance(value, dict):return None
    version, verified, expires, rates = (value.get(key) for key in ('version', 'verified_at', 'expires_at', 'rates'))
    if not isinstance(version, str) or not ADMIN_VERSION.fullmatch(version):return None
    if type(verified) is not int or type(expires) is not int:return None
    if not 0 < expires - verified <= MAX_CONFIRMATION_DAYS * 86400 or not isinstance(rates, dict):return None
    confirmed = {}
    for model, reference in RATES.items():
        try:confirmed[model] = normalized_rates(rates.get(model), reference)
        except ValueError:continue
    confirmed_by = value.get('confirmed_by')
    return {'version': version, 'source': SOURCE, 'verified_at': verified, 'expires_at': expires,
            'origin': 'administrator', 'confirmed_by': confirmed_by[:64] if isinstance(confirmed_by, str) else '',
            'rates': confirmed}


def _stored_value():
    """Read the confirmed catalog row in its own short read-only session."""
    from .db import Session, Setting
    try:
        with Session() as session:
            row = session.get(Setting, STORED_KEY)
            return row.value if row is not None else None
    except Exception:  # noqa: BLE001 - an unreadable row cannot extend a window
        # Falling back can never extend validity: the bundled catalog keeps its
        # own reviewed window and fails closed after it.
        return None


def active_catalog(stored=None):
    """Return whichever of the bundled and confirmed catalogs was verified last.

    A newer release supersedes an older confirmation, and an expired
    confirmation is never replaced by older bundled rates.
    """
    bundled = bundled_catalog()
    confirmed = stored_catalog(_stored_value() if stored is None else stored)
    return confirmed if confirmed is not None and confirmed['verified_at'] > bundled['verified_at'] else bundled


_call_catalog = ContextVar('ai_price_call_catalog', default=None)


@contextmanager
def call_snapshot():
    """Price one provider call with a single catalog snapshot.

    The reservation ceiling is quoted when the call is admitted, but usage is
    estimated only after the reply arrives. An administrator can confirm new
    rates in between, so both must read the same snapshot: the settled charge
    then matches the pricing version recorded on its reservation, and a
    confirmation (or expiry) only affects calls admitted after it.
    """
    token = _call_catalog.set(active_catalog())
    try:
        yield
    finally:
        _call_catalog.reset(token)


def call_catalog():
    """The current call's pinned snapshot, or the effective catalog outside a call."""
    pinned = _call_catalog.get()
    return pinned if pinned is not None else active_catalog()


def revision(catalog):
    """Opaque revision of a catalog's content, for optimistic confirmation."""
    body = [catalog['version'], catalog['verified_at'], catalog['expires_at'],
            sorted((model, list(rates)) for model, rates in catalog['rates'].items())]
    return hashlib.sha256(json.dumps(body, separators=(',', ':')).encode('utf-8')).hexdigest()


def confirmation(rates, days, actor, now, current):
    """Build a stored administrator confirmation and its audit summary.

    ``rates`` maps every bundled model ID to its four confirmed rate strings
    (``None`` where the bundled catalog has no cache-write price). Raises
    ValueError for anything that cannot become a complete confirmed catalog.
    """
    if type(days) is not int or not 1 <= days <= MAX_CONFIRMATION_DAYS:
        raise ValueError('Choose a validity period of 1 to ' + str(MAX_CONFIRMATION_DAYS) + ' days.')
    if not isinstance(rates, dict) or set(rates) != set(RATES):
        raise ValueError('Confirm rates for exactly the catalogued models.')
    confirmed = {}
    for model, reference in RATES.items():
        try:confirmed[model] = normalized_rates(rates[model], reference)
        except ValueError as error:raise ValueError(model + ': ' + str(error)) from None
    verified = int(now)
    if verified <= VERIFIED_AT:
        raise ValueError('The controller clock predates the bundled catalog verification; correct the clock first.')
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(verified))
    value = {'version': 'admin-' + stamp, 'verified_at': verified, 'expires_at': verified + days * 86400,
             'confirmed_by': actor[:64], 'rates': {model: list(values) for model, values in confirmed.items()}}
    changes = []
    for model, values in confirmed.items():
        before = current['rates'].get(model)
        for field, old, new in zip(RATE_FIELDS, before or (None,) * len(RATE_FIELDS), values):
            if old is None and new is None:continue
            if before is None or Decimal(old) != Decimal(new):
                changes.append(model + ' ' + field + ' ' + (old if before is not None and old is not None else 'unpriced') + ' -> ' + new)
    return value, changes


def catalog_status(now=None, catalog=None):
    """Return bounded public catalog metadata without exposing request data."""
    now = time.time() if now is None else now
    catalog = active_catalog() if catalog is None else catalog
    administrator = catalog['origin'] == 'administrator'
    name = 'administrator-confirmed' if administrator else 'bundled'
    if now < catalog['verified_at']:
        state = 'not_yet_valid'
        reason = 'The controller clock predates this price catalog verification.'
    elif now >= catalog['expires_at']:
        state = 'expired'
        reason = ('The ' + name + ' public-price catalog has expired. Re-confirm current prices in Settings '
                  'or deploy a reviewed catalog update.')
    else:
        state = 'fresh'
        reason = 'The ' + name + ' public-price catalog is within its reviewed validity window.'
    return {'version': catalog['version'], 'source': catalog['source'], 'verified_at': catalog['verified_at'],
            'expires_at': catalog['expires_at'], 'origin': catalog['origin'], 'confirmed_by': catalog['confirmed_by'],
            'state': state, 'fresh': state == 'fresh', 'reason': reason}


def public_catalog(now=None):
    """Settings view: status, revision and the effective and bundled rates."""
    catalog = active_catalog()
    rates = lambda table: {model: dict(zip(RATE_FIELDS, values)) for model, values in table.items()}
    return {**catalog_status(now, catalog), 'revision': revision(catalog), 'rates': rates(catalog['rates']),
            'bundled_rates': rates(RATES), 'bundled_version': VERSION, 'bundled_expires_at': EXPIRES_AT,
            'max_confirmation_days': MAX_CONFIRMATION_DAYS}


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
    catalog = call_catalog()
    model = ALIASES.get(result['response_model'], result['response_model'])
    if model not in catalog['rates']:
        result['reason'] = 'The returned model has no verified price in the current price catalog.'
        return result
    rates = catalog['rates'][model]
    modern = rates[3] is not None
    if modern and 'cache_write_tokens' not in data['usage'].get('input_tokens_details', {}):
        result['reason'] = 'Cache-write usage was not returned; a reliable estimate is unavailable.'
        return result
    multiplier = tier_multipliers(model)
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
        'estimated_usd': format(cost, 'f'), 'currency': 'USD', 'version': catalog['version'],
        'source': catalog['source'],
        'model': model, 'service_tier': result['service_tier'],
        'per_million': dict(zip(('input', 'cached_input', 'output', 'cache_write'), (format(v, 'f') for v in prices))),
        'cache_ttl': ttl if modern else None,
    })
    return result


def tier_multipliers(model):
    """Verified processing-tier price multipliers for a catalogued model.

    Shared by estimate() and reservation() so the settled estimate and the
    reservation ceiling cannot diverge. Old-model priority/Flex prices are not
    inferred from modern multipliers.
    """
    multipliers = {'default': '1'}
    if RATES[model][3] is not None: multipliers.update(flex='0.5', priority='2', fast='2')
    if model in ('gpt-6-astra', 'gpt-6.1-sol'): multipliers['ultrafast'] = '6'
    return multipliers


UNPRICED_MODEL_REASON = 'The selected model has no verified price for a safe reservation.'


def model_status(model, now=None):
    """Return whether the effective catalog can price a saved model ID at all.

    Pure and read-only. It checks only catalog validity and the alias-resolved
    model. A specific call can still be refused for its tier, tools, output
    bound or context size, so ``ok`` never promises that a call will be admitted.
    """
    catalog = active_catalog()
    status = catalog_status(now, catalog)
    version = catalog['version']
    if not status['fresh']:
        return {'ok': False, 'code': 'catalog', 'model': '', 'reason': status['reason'], 'version': version}
    requested = identifier(model)
    if not requested:
        return {'ok': False, 'code': 'model', 'model': '', 'version': version,
                'reason': 'The saved model ID is not a catalog identifier, so no price can be verified for a safe reservation.'}
    resolved = ALIASES.get(requested, requested)
    if resolved not in catalog['rates']:
        return {'ok': False, 'code': 'model', 'model': requested, 'reason': UNPRICED_MODEL_REASON, 'version': version}
    return {'ok': True, 'code': '', 'model': resolved, 'reason': '', 'version': version}


def reservation(payload, now=None):
    """Return a conservative USD ceiling before a capped provider call.

    UTF-8 JSON bytes are a safe upper bound for token count for the bounded text
    requests Mr Patchy sends. Unknown models, tiers, output bounds, tool fees or
    long-context prices fail closed instead of becoming a zero-dollar estimate.
    """
    effective = call_catalog()
    catalog = catalog_status(now, effective)
    if not catalog['fresh']:
        return {'ok': False, 'reason': catalog['reason'], 'catalog': catalog}
    requested = identifier(payload.get('model'))
    model = ALIASES.get(requested, requested)
    if model not in effective['rates']:
        return {'ok': False, 'reason': UNPRICED_MODEL_REASON}
    output = payload.get('max_output_tokens')
    if type(output) is not int or not 1 <= output <= 1_000_000:
        return {'ok': False, 'reason': 'The request has no bounded output-token maximum for a safe reservation.'}
    if payload.get('tools'):
        return {'ok': False, 'reason': 'Tool fees are not available for a safe reservation.'}
    tier = payload.get('service_tier', 'default')
    rates = effective['rates'][model]; modern = rates[3] is not None
    multipliers = tier_multipliers(model)
    if tier not in multipliers:
        return {'ok': False, 'reason': 'The requested processing tier has no verified price for a safe reservation.'}
    excluded = {'model', 'store', 'max_output_tokens', 'service_tier', 'prompt_cache_options'}
    tokenized = {key: value for key, value in payload.items() if key not in excluded}
    try: input_ceiling = len(json.dumps(tokenized, sort_keys=True, separators=(',', ':')).encode('utf-8'))
    except (TypeError, ValueError, UnicodeError):
        return {'ok': False, 'reason': 'The request cannot be bounded for a safe reservation.'}
    if input_ceiling > 1_000_000 or (modern and input_ceiling > 272000):
        return {'ok': False, 'reason': 'Long-context pricing is not available for a safe reservation.'}
    options = payload.get('prompt_cache_options') or {}
    ttl = options.get('ttl', '30m') if isinstance(options, dict) else ''
    if ttl not in ('30m', '12h'):
        return {'ok': False, 'reason': 'Prompt-cache pricing is not available for a safe reservation.'}
    factor = Decimal(multipliers[tier])
    prices = [Decimal(value) * factor if value is not None else Decimal(0) for value in rates]
    if ttl == '12h' and modern: prices[3] *= 2
    input_rate = max(prices[0], prices[1], prices[3])
    amount = (Decimal(input_ceiling) * input_rate + Decimal(output) * prices[2]) / Decimal(1_000_000)
    amount = amount.quantize(Decimal('0.000001'), rounding=ROUND_CEILING)
    return {'ok': True, 'amount_usd': amount, 'model': model, 'service_tier': tier,
            'pricing_version': effective['version'], 'pricing_source': effective['source'],
            'input_token_ceiling': input_ceiling, 'output_token_ceiling': output}
