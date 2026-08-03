# Attack: Information Disclosure via Plaintext Token Leakage

## STRIDE Category
**Information Disclosure** — Sensitive data is exposed to unauthorized parties.

## Attack Description
OCPP 1.6-J messages contain fields that are intended for diagnostic or
vendor-specific purposes. In the `StatusNotification` message, the `info`
field (max 50 characters) is for "Additional free-text information about
the error," and the `vendorId` field identifies the vendor. Neither field
is designed to carry security-sensitive data.

However, in practice, Charge Point firmware developers sometimes
inadvertently include sensitive data in these fields during debugging:
- `idTag` values (RFID card identifiers)
- Session tokens or API keys
- JWT tokens or authentication credentials
- Internal user identifiers

When these messages are logged by the CSMS (which is standard practice for
monitoring and debugging), the sensitive data ends up in **plaintext log
files**. These logs may be:
- Stored without encryption
- Accessible to support staff who shouldn't see authentication tokens
- Shipped to third-party log aggregation services
- Retained for long periods without proper data handling

## Detection Signals
1. Search the `info` field of `StatusNotification` for patterns matching:
   - `idTag=` followed by an identifier
   - `token=` or `sk_live_` or `sk_test_` (API key patterns)
   - `eyJ` prefix (base64-encoded JWT tokens)
   - Known `idTag` values from the authorized list
2. Search the `vendorId` field for similar patterns.
3. Search the `data` field in `DataTransfer` messages (if used).
4. Check for any field containing what looks like a credential in plaintext.

## Impact
- Credential theft: leaked tokens can be used to impersonate users
- Privacy violation: RFID tag IDs can be linked to individual users
- Compliance risk: GDPR, PCI-DSS, and similar regulations prohibit
  logging sensitive credentials in plaintext
- Supply chain risk: if logs are sent to third parties

## Relevant OCPP Spec Sections
- Section 5.18: StatusNotification (info and vendorId fields)
- Section 5.7: DataTransfer (vendor-specific data exchange)
- Section 7.37: StatusNotification.req field definitions

## OCPP Security Recommendation
Charge Point firmware should never include authentication tokens, idTags,
or session credentials in diagnostic fields. The CSMS should implement
**log sanitization** to detect and redact sensitive patterns before
persisting log entries. OCPP 2.0.1 provides improved security profiles
that include guidelines for handling sensitive data in messages.
