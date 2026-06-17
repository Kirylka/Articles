/**
 * PII redaction hooks for the audit trail.
 *
 * Redaction is applied only to what gets *written to the audit log* — never to
 * the arguments the real handler executes with. The default redactor masks a
 * few common PII shapes (emails, long digit runs that look like card/account
 * numbers) and a configurable set of sensitive field names.
 */

/** Transforms a value before it is recorded in the audit log. */
export type Redactor = (value: unknown) => unknown;

const SENSITIVE_FIELDS = new Set([
  "password",
  "secret",
  "token",
  "apikey",
  "api_key",
  "authorization",
  "ssn",
  "cardnumber",
  "card_number",
  "cvv",
  "pin",
]);

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const LONG_DIGITS_RE = /\b\d[\d -]{10,}\d\b/g;

function maskString(value: string): string {
  return value
    .replace(EMAIL_RE, "[redacted-email]")
    .replace(LONG_DIGITS_RE, "[redacted-number]");
}

/**
 * Build a redactor that masks the given field names (case-insensitive) and,
 * by default, also masks emails and long digit sequences inside strings.
 */
export function redactFields(
  fields: Iterable<string> = SENSITIVE_FIELDS,
  options: { maskStrings?: boolean } = {},
): Redactor {
  const maskStrings = options.maskStrings ?? true;
  const blocked = new Set([...fields].map((f) => f.toLowerCase()));

  const walk = (value: unknown): unknown => {
    if (typeof value === "string") return maskStrings ? maskString(value) : value;
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(value)) {
        out[key] = blocked.has(key.toLowerCase()) ? "[redacted]" : walk(val);
      }
      return out;
    }
    return value;
  };

  return walk;
}

/** The default redactor: masks common sensitive field names and PII strings. */
export const defaultRedactor: Redactor = redactFields();

/** A redactor that changes nothing. */
export const identityRedactor: Redactor = (value) => value;
