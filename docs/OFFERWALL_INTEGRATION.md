# Publisher integration

Each publisher receives two independent credentials in Django Admin:

- a signing secret for entry links and verification of RM Wins postbacks;
- an `ow_live_...` API key for optional server-side inventory reads.

Plaintext credentials are displayed once. Store them in a secret manager and rotate them from
Django Admin if they are exposed.

## Signed wall entry

Send a respondent to:

```text
GET https://offerwall.rmwinsights.com/wall/{publisher_slug}/
    ?uid={external_user_id}
    &ts={unix_timestamp}
    &nonce={unique_nonce}
    &sig={hex_hmac_sha256}
```

Build the signature over this exact UTF-8 string, including newline separators:

```text
offerwall-entry-v1
{publisher_slug}
{external_user_id}
{unix_timestamp}
{nonce}
```

Then calculate lowercase `HMAC-SHA256(signing_secret, canonical_string)`. The nonce must contain
12–80 URL-safe letters, digits, `_` or `-`, and must not be reused for another user. Entry links are
short-lived; RM Wins redirects a valid entry to a signed server-side wall session.

## Inventory API

```text
GET https://offerwall.rmwinsights.com/api/v1/offerwall/offers/?uid={external_user_id}
X-Offerwall-Key: ow_live_...
```

The response contains publisher details, session expiry, a signed wall URL and currently eligible
offers with signed click URLs. API keys must only be used server-to-server.

## Outcome postback

When postbacks are enabled for a publisher, RM Wins sends JSON to its configured HTTPS callback.
The payload includes:

- `event`, `event_id`, `click_id` and `transaction_id`;
- `user_id` and `offer_id`;
- `status`, `status_label`, `term_reason` and `term_category`;
- `credited`, `amount`, `currency` and `verified`;
- `occurred_at`.

Headers:

```text
X-Offerwall-Event: {event_id}
X-Offerwall-Timestamp: {unix_timestamp}
X-Offerwall-Signature: sha256={signature}
```

To verify the postback, SHA-256 hash the exact raw request body as lowercase hex and build:

```text
offerwall-postback-v1
{X-Offerwall-Timestamp}
{X-Offerwall-Event}
{sha256_hex_of_raw_body}
```

Calculate `HMAC-SHA256(signing_secret, canonical_string)` and compare it to the header signature
with a constant-time comparison. Reject stale timestamps and duplicate event IDs in the publisher
system. RM Wins retries non-2xx responses with bounded exponential backoff and never follows
callback redirects.

Credits are emitted only for provider-verified completions. Termination and over-quota outcomes
carry the same normalized reason/category received by RM Wins. A later authoritative reversal is
sent with a negative amount.
