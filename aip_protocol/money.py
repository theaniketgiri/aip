"""
AIP Money — exact monetary arithmetic in integer minor units.

Payment authorization cannot use binary floats. `0.1 + 0.2 != 0.3`, and a
limit check that is wrong by one ulp is a limit check that can be walked
through. Every amount in AIP is therefore carried and compared as an
integer number of MINOR units (paise, cents, satang).

    ₹450.75  -> 45075 minor units (exponent 2)
    ¥1200    -> 1200  minor units (exponent 0)

Floats are still accepted at the API boundary for backwards compatibility,
but they are converted through `Decimal(str(value))` — never through binary
float arithmetic — and rejected if they carry more precision than the
currency allows.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

# ISO 4217 exponents for currencies that are not the 2-decimal default.
_CURRENCY_EXPONENTS: dict[str, int] = {
    "JPY": 0, "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0,
    "BHD": 3, "KWD": 3, "OMR": 3, "TND": 3, "JOD": 3,
}
DEFAULT_EXPONENT = 2


class MoneyError(ValueError):
    """Raised when an amount cannot be represented exactly in minor units."""


def exponent_for(currency: str) -> int:
    """ISO 4217 minor-unit exponent for a currency code. Defaults to 2."""
    return _CURRENCY_EXPONENTS.get((currency or "").upper(), DEFAULT_EXPONENT)


def to_minor(value: int | float | str | Decimal, currency: str = "USD") -> int:
    """
    Convert a major-unit amount to exact integer minor units.

    >>> to_minor(450.75, "INR")
    45075
    >>> to_minor("0.1", "USD") + to_minor("0.2", "USD") == to_minor("0.3", "USD")
    True

    Raises MoneyError if the value has more precision than the currency
    supports (e.g. ₹1.005), rather than silently rounding money away.
    """
    exponent = exponent_for(currency)
    try:
        # str() first: Decimal(0.1) is 0.1000000000000000055511151231257827,
        # Decimal("0.1") is exactly 0.1.
        dec = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError) as exc:
        raise MoneyError(f"Not a valid monetary amount: {value!r}") from exc

    if not dec.is_finite():
        raise MoneyError(f"Monetary amount must be finite, got {value!r}")

    scaled = dec.scaleb(exponent)
    if scaled == scaled.to_integral_value():
        return int(scaled)

    # A float input may carry binary representation noise rather than real
    # precision: 0.1 + 0.2 is 0.30000000000000004, which means ₹0.30, not an
    # attempt to pay a fraction of a paisa. Absorb noise, reject real
    # over-precision (₹1.005 is genuinely unrepresentable and must not be
    # silently rounded away).
    if isinstance(value, float):
        rounded = scaled.to_integral_value(rounding=ROUND_HALF_EVEN)
        drift = abs(scaled - rounded)
        tolerance = max(Decimal("1e-6"), abs(scaled) * Decimal("1e-12"))
        if drift <= tolerance:
            return int(rounded)

    raise MoneyError(
        f"{value!r} has more precision than {currency.upper()} supports "
        f"({exponent} decimal places). Pass an exact amount or use minor units."
    )


def from_minor(minor: int, currency: str = "USD") -> Decimal:
    """Convert integer minor units back to an exact major-unit Decimal."""
    return Decimal(int(minor)).scaleb(-exponent_for(currency))


def format_minor(minor: int, currency: str = "USD") -> str:
    """Human-readable amount, e.g. format_minor(45075, 'INR') -> '450.75 INR'."""
    return f"{from_minor(minor, currency)} {currency.upper()}"


def extract_amount_minor(parameters: dict, currency: str) -> int | None:
    """
    Pull a monetary amount out of intent parameters, preferring exact forms.

    Resolution order:
      1. `amount_minor` — integer minor units (preferred, always exact)
      2. `amount`       — major units, converted exactly via Decimal

    Returns None when the intent carries no amount at all.
    """
    if "amount_minor" in parameters:
        raw = parameters["amount_minor"]
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise MoneyError(f"amount_minor must be an integer, got {raw!r}")
        return raw

    if "amount" in parameters:
        raw = parameters["amount"]
        if raw is None or isinstance(raw, bool):
            return None
        if not isinstance(raw, (int, float, str, Decimal)):
            return None
        return to_minor(raw, currency)

    return None
