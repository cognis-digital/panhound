# Demo 01 - Basic PAN & CVV leak scan

## What this shows

`demos/01-basic/checkout_fixture.json` is a realistic-looking test fixture of
the kind that quietly ends up committed to a repo. It contains:

- A **Visa** PAN (`4111 11XX XXXX 1111`) - a valid Luhn test number.
- A **Mastercard** PAN written with spaces (`5500 00XX XXXX 0004`).
- An **Amex** PAN written with hyphens (`3782-82XXXX-0005`).
- A labeled **CVV** (`"cvv": "1XX"`).
- Decoys that must NOT be flagged: a phone number, an order id, a timestamp,
  and an invalid 16-digit number that fails Luhn.

## Run it

```bash
# Human-readable table
python -m panhound scan demos/01-basic

# JSON for CI / jq
python -m panhound scan --format json demos/01-basic
```

## Expected result

- Exit code **1** (leaks found -> CI gate fails).
- **4 findings**: 3 PANs (visa, mastercard, amex) + 1 CVV.
- The decoy phone/order-id/timestamp and the Luhn-invalid number are NOT
  reported.
- All emitted values are masked (e.g. `411111******1111`); raw card numbers
  never appear in PANHOUND output.
