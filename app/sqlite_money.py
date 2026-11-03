"""Bounded-memory exact sum at the ledger's nine-place SQLite read precision.

SQLite NUMERIC storage uses binary floats, so native SUM can accumulate rounding
errors. Normalize each value exactly as SQLAlchemy's Numeric(..., 9) reader did,
then accumulate integer nano-dollars. Return text to avoid converting the total
back to a float. MySQL uses its native exact DECIMAL SUM instead.
"""


class MoneySum:
    def __init__(self):
        self.units=0

    def step(self, value):
        if value is not None:
            self.units+=int(format(value, '.9f').replace('.', ''))

    def finalize(self):
        whole, fraction=divmod(abs(self.units), 1_000_000_000)
        return ('-' if self.units<0 else '')+f'{whole}.{fraction:09d}'
