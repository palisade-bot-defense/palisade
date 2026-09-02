// Client-side verifier for PALISADE human assurance assertions.
//
// Messages and calls make a person's client the relying party, so the verifier
// has to run where that client runs: a browser, a phone, a desktop app. This
// package is that verifier. It is a second implementation of the frozen
// contract in pkg/palisadeassurance, and it is held to the same conformance
// suite plus a set of documents the Go implementation actually signed, so the
// two cannot drift by a byte without a test noticing.
//
// It performs no network call and reads no clock of its own. The caller
// supplies the signing key, the audience and the evaluation time. It never
// holds a signing key or a binding secret: a client verifies, it does not mint.

export const SCHEMA_VERSION = "palisade.human-assurance-assertion.v2";

/** One action on the transaction surface, verified once before the action. */
export const PROFILE_REQUEST = "request";
/**
 * One message, minted at send and verified at read by the recipient's own
 * client. PALISADE never sees the content: the sender commits to it and the
 * commitment is what is signed.
 */
export const PROFILE_CONTENT = "content";
/** One interval of one call channel, re-issued every interval. */
export const PROFILE_CHANNEL = "channel";

export const LEVEL_UNATTRIBUTED = 0;
export const LEVEL_BEHAVIORAL = 1;
export const LEVEL_INTERACTIVE = 2;
export const LEVEL_ATTESTED_DEVICE = 3;
export const LEVEL_ISSUER_VERIFIED = 4;
export const LEVEL_ISSUER_UNIQUE = 5;

/** The top of the documented ladder. */
export const MAXIMUM_SPECIFIED_LEVEL = LEVEL_ISSUER_UNIQUE;
/**
 * The highest level this implementation accepts. It matches the Go reference
 * and, like it, is raised by a mechanism that verifies the added evidence and
 * a measurement that bounds its cost — never by editing this constant.
 */
export const MAXIMUM_SUPPORTED_LEVEL = LEVEL_BEHAVIORAL;

export const MAXIMUM_LIFETIME_MS = 5 * 60 * 1000;
export const MAXIMUM_CLOCK_SKEW_MS = 30 * 1000;
export const MAXIMUM_DOCUMENT_BYTES = 8 << 10;
/**
 * Validity bound of a content-profile assertion. On the message surface
 * validity and freshness diverge: the assertion stays verifiable for as long
 * as a message plausibly waits to be read, while issued_at records how old the
 * evidence was when the message was sent. A recipient must show both.
 */
export const MAXIMUM_CONTENT_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * Validity bound of a channel-profile assertion. Short by design: a call whose
 * last attestation is older than this has lost its claim to presence.
 */
export const MAXIMUM_CHANNEL_LIFETIME_MS = 2 * 60 * 1000;

// The separators are NUL bytes, byte-identical to the Go constant. They are
// built at runtime so this source file contains no NUL and no escape that a
// tool could silently rewrite.
const NUL = String.fromCharCode(0);
const DOMAIN_SEPARATOR = "PALISADE" + NUL + "HUMAN-ASSURANCE-ASSERTION" + NUL + "V2" + NUL;

const PROFILES = [PROFILE_REQUEST, PROFILE_CONTENT, PROFILE_CHANNEL] as const;

/** Validity bound for a binding profile, in milliseconds. */
export function lifetimeFor(profile: string): number {
  switch (profile) {
    case PROFILE_CONTENT:
      return MAXIMUM_CONTENT_LIFETIME_MS;
    case PROFILE_CHANNEL:
      return MAXIMUM_CHANNEL_LIFETIME_MS;
    default:
      return MAXIMUM_LIFETIME_MS;
  }
}


const ASSURANCE_SOURCES = ["behavioral", "challenge", "device", "issuer"] as const;
const UNIQUENESS_SCOPES = ["none", "device", "issuer"] as const;
const AGENT_PROVENANCES = ["none", "declared", "authorized", "verified_purpose"] as const;
const REQUEST_ACTIONS = [
  "read", "write", "create", "update", "delete", "search", "compare",
  "login", "logout", "register", "checkout", "purchase", "other",
] as const;
const ENDPOINT_CLASSES = [
  "public_content", "compare_index", "compare_noindex", "challenge_worker",
  "other_public", "account", "login", "checkout", "other",
] as const;

const REQUIRED_SOURCES: Record<number, readonly string[]> = {
  [LEVEL_UNATTRIBUTED]: [],
  [LEVEL_BEHAVIORAL]: ["behavioral"],
  [LEVEL_INTERACTIVE]: ["behavioral", "challenge"],
  [LEVEL_ATTESTED_DEVICE]: ["behavioral", "challenge", "device"],
  [LEVEL_ISSUER_VERIFIED]: ["behavioral", "challenge", "device", "issuer"],
  [LEVEL_ISSUER_UNIQUE]: ["behavioral", "challenge", "device", "issuer"],
};

const STABLE_VERSION = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const REASON_CODE = /^[a-z][a-z0-9_]{2,63}$/;
const AUDIENCE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const DOCUMENT_FIELDS = ["payload", "key_id", "signature"] as const;
const PAYLOAD_FIELDS = [
  "schema_version", "assurance_level", "assurance_sources", "reason_codes",
  "uniqueness_scope", "agent_provenance", "binding", "policy_version",
  "model_version", "issued_at", "expires_at", "nonce",
] as const;
// Each profile carries exactly its own fields. A binding that carries another
// profile's field could be read under the wrong profile, and is refused.
const BINDING_FIELDS: Record<string, readonly string[]> = {
  [PROFILE_REQUEST]: ["profile", "session_binding", "request_action", "endpoint_class", "audience"],
  [PROFILE_CONTENT]: ["profile", "session_binding", "content_commitment", "audience"],
  [PROFILE_CHANNEL]: ["profile", "session_binding", "channel_binding", "interval_index", "audience"],
};

export type VerificationFailure = "invalid" | "expired" | "unsupported_level";

/**
 * Every failure carries one of three codes. As in the Go implementation,
 * "invalid" covers structure, vocabulary, binding, signature and consistency
 * together; a relying service must not branch on a finer cause.
 */
export class AssertionError extends Error {
  readonly code: VerificationFailure;
  constructor(code: VerificationFailure) {
    super(`human assurance assertion ${code}`);
    this.name = "AssertionError";
    this.code = code;
  }
}

/**
 * Ties an assertion to one audience and one thing on one surface. The profile
 * says which optional fields are present; every other profile's fields must be
 * absent. Field order here is the canonical signing order.
 */
export interface Binding {
  readonly profile: string;
  readonly session_binding: string;
  /** request profile only. */
  readonly request_action?: string;
  /** request profile only. */
  readonly endpoint_class?: string;
  /**
   * content profile only: base64url SHA-256 of the message content, computed
   * by the sender. The signer never sees the content.
   */
  readonly content_commitment?: string;
  /** channel profile only: opaque per-audience channel commitment. */
  readonly channel_binding?: string;
  /** channel profile only: the re-attestation interval this covers. */
  readonly interval_index?: number;
  readonly audience: string;
}

export interface Payload {
  readonly schema_version: string;
  readonly assurance_level: number;
  readonly assurance_sources: readonly string[];
  readonly reason_codes: readonly string[];
  readonly uniqueness_scope: string;
  readonly agent_provenance: string;
  readonly binding: Binding;
  readonly policy_version: string;
  readonly model_version: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly nonce: string;
}

export interface Verified {
  readonly payload: Payload;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

/**
 * Reports whether an accepted assertion meets a relying service's minimum.
 * Insufficient assurance is an ordinary policy input, not an error.
 */
/**
 * Reports whether a content-profile assertion was minted for exactly this
 * message. A recipient calls it with the bytes it received: an assertion
 * forwarded with a different message, or a message altered after sending,
 * fails here even though the signature still verifies.
 */
export async function matchesContent(verified: Verified, content: Uint8Array): Promise<boolean> {
  if (verified.payload.binding.profile !== PROFILE_CONTENT) {
    return false;
  }
  // Copy into a fresh ArrayBuffer-backed view: WebCrypto refuses a view over a
  // SharedArrayBuffer, and the caller may hand us one.
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(content)));
  return verified.payload.binding.content_commitment === encodeBase64Url(digest);
}

export function satisfies(verified: Verified, minimumLevel: number, requireUnique: boolean): boolean {
  if (verified.payload.assurance_level < minimumLevel) {
    return false;
  }
  return !requireUnique || verified.payload.uniqueness_scope !== "none";
}

/** Identifies a signing key without revealing it: the first eight bytes of its SHA-256, hex encoded. */
export async function keyId(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(publicKey)));
  return Array.from(digest.subarray(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Accepts assertions signed by one key for one audience. Stateless; the
 * caller supplies the evaluation time so the verifier never reads a clock.
 */
export class Verifier {
  private constructor(
    private readonly key: CryptoKey,
    private readonly keyIdentifier: string,
    private readonly audience: string,
  ) {}

  static async create(publicKey: Uint8Array, audience: string): Promise<Verifier> {
    if (publicKey.length !== 32 || !AUDIENCE.test(audience)) {
      throw new AssertionError("invalid");
    }
    const key = await crypto.subtle.importKey("raw", Uint8Array.from(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return new Verifier(key, await keyId(publicKey), audience);
  }

  /**
   * Checks structure, vocabulary, binding, signature and validity window, in
   * that order, exactly as the reference implementation does, so both produce
   * the same failure code for the same document.
   */
  async verify(encoded: string | Uint8Array, now: Date): Promise<Verified> {
    const bytes = typeof encoded === "string" ? new TextEncoder().encode(encoded) : encoded;
    if (bytes.length === 0 || bytes.length > MAXIMUM_DOCUMENT_BYTES) {
      throw new AssertionError("invalid");
    }
    const text = typeof encoded === "string" ? encoded : new TextDecoder("utf-8", { fatal: true }).decode(bytes);

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new AssertionError("invalid");
    }
    const document = requireFields(parsed, DOCUMENT_FIELDS);
    const payloadObject = requireFields(document["payload"], PAYLOAD_FIELDS);
    // The profile decides which fields the binding must carry, so it is read
    // before completeness is checked: an unknown profile fails here rather than
    // being validated as a request.
    const rawBinding = payloadObject["binding"];
    const profile =
      rawBinding !== null && typeof rawBinding === "object" && typeof (rawBinding as Record<string, unknown>)["profile"] === "string"
        ? ((rawBinding as Record<string, unknown>)["profile"] as string)
        : "";
    const bindingObject = requireFields(rawBinding, BINDING_FIELDS[profile] ?? []);
    const payload = decodePayload(payloadObject, bindingObject);
    validatePayload(payload);

    const keyIdentifier = document["key_id"];
    const signatureText = document["signature"];
    if (typeof keyIdentifier !== "string" || typeof signatureText !== "string") {
      throw new AssertionError("invalid");
    }
    if (payload.binding.audience !== this.audience || keyIdentifier !== this.keyIdentifier) {
      throw new AssertionError("invalid");
    }
    const signature = decodeBase64Url(signatureText);
    if (signature === null || signature.length !== 64) {
      throw new AssertionError("invalid");
    }
    const message = signingMessage(canonicalize(payload));
    if (!(await crypto.subtle.verify({ name: "Ed25519" }, this.key, Uint8Array.from(signature), Uint8Array.from(message)))) {
      throw new AssertionError("invalid");
    }

    const { issuedAt, expiresAt } = validityWindow(payload, now);
    if (payload.assurance_level > MAXIMUM_SUPPORTED_LEVEL) {
      throw new AssertionError("unsupported_level");
    }
    return { payload, issuedAt, expiresAt };
  }
}

// --- structure -----------------------------------------------------------

/**
 * Rejects a document whose fields are absent, null or unknown. JSON.parse, like
 * Go's decoder, would happily give an absent evidence list a default; the
 * contract is closed and every field is required.
 */
function requireFields(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AssertionError("invalid");
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object);
  if (keys.length !== names.length) {
    throw new AssertionError("invalid");
  }
  for (const name of names) {
    if (!Object.prototype.hasOwnProperty.call(object, name) || object[name] === null || object[name] === undefined) {
      throw new AssertionError("invalid");
    }
  }
  return object;
}

function requireString(value: unknown): string {
  if (typeof value !== "string") {
    throw new AssertionError("invalid");
  }
  return value;
}

function requireStrings(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new AssertionError("invalid");
  }
  return value.map(requireString);
}

function decodePayload(object: Record<string, unknown>, bindingObject: Record<string, unknown>): Payload {
  const level = object["assurance_level"];
  if (typeof level !== "number" || !Number.isInteger(level)) {
    throw new AssertionError("invalid");
  }
  return {
    schema_version: requireString(object["schema_version"]),
    assurance_level: level,
    assurance_sources: requireStrings(object["assurance_sources"]),
    reason_codes: requireStrings(object["reason_codes"]),
    uniqueness_scope: requireString(object["uniqueness_scope"]),
    agent_provenance: requireString(object["agent_provenance"]),
    binding: decodeBinding(bindingObject),
    policy_version: requireString(object["policy_version"]),
    model_version: requireString(object["model_version"]),
    issued_at: requireString(object["issued_at"]),
    expires_at: requireString(object["expires_at"]),
    nonce: requireString(object["nonce"]),
  };
}

// --- vocabulary ----------------------------------------------------------

function validatePayload(payload: Payload): void {
  if (payload.schema_version !== SCHEMA_VERSION) {
    throw new AssertionError("invalid");
  }
  if (payload.assurance_level < LEVEL_UNATTRIBUTED || payload.assurance_level > MAXIMUM_SPECIFIED_LEVEL) {
    throw new AssertionError("invalid");
  }
  if (!STABLE_VERSION.test(payload.policy_version) || !STABLE_VERSION.test(payload.model_version)) {
    throw new AssertionError("invalid");
  }
  if (!includes(UNIQUENESS_SCOPES, payload.uniqueness_scope) || !includes(AGENT_PROVENANCES, payload.agent_provenance)) {
    throw new AssertionError("invalid");
  }
  if (payload.nonce.length !== 22 || !isBase64Url(payload.nonce)) {
    throw new AssertionError("invalid");
  }
  validateSources(payload);
  validateReasonCodes(payload.reason_codes);
  validateBinding(payload.binding);
  // Uniqueness is an issuer property. A deployment cannot assert a distinct
  // subject without the evidence class that establishes one.
  if (payload.uniqueness_scope === "issuer" && !payload.assurance_sources.includes("issuer")) {
    throw new AssertionError("invalid");
  }
  if (payload.uniqueness_scope === "device" && !payload.assurance_sources.includes("device")) {
    throw new AssertionError("invalid");
  }
}

function validateSources(payload: Payload): void {
  if (payload.assurance_sources.length > ASSURANCE_SOURCES.length) {
    throw new AssertionError("invalid");
  }
  const seen = new Set<string>();
  for (const source of payload.assurance_sources) {
    if (!includes(ASSURANCE_SOURCES, source) || seen.has(source)) {
      throw new AssertionError("invalid");
    }
    seen.add(source);
  }
  for (const required of REQUIRED_SOURCES[payload.assurance_level] ?? []) {
    if (!seen.has(required)) {
      throw new AssertionError("invalid");
    }
  }
}

function validateReasonCodes(codes: readonly string[]): void {
  if (codes.length > 16) {
    throw new AssertionError("invalid");
  }
  const seen = new Set<string>();
  for (const code of codes) {
    if (!REASON_CODE.test(code) || seen.has(code)) {
      throw new AssertionError("invalid");
    }
    seen.add(code);
  }
}

function validateBinding(binding: Binding): void {
  if (binding.session_binding.length !== 43 || !isBase64Url(binding.session_binding)) {
    throw new AssertionError("invalid");
  }
  if (!AUDIENCE.test(binding.audience)) {
    throw new AssertionError("invalid");
  }
  // Each profile must carry exactly its own fields. A request binding with a
  // content commitment, or a content binding with an endpoint class, could be
  // read under the wrong profile and is refused rather than tolerated.
  const absent = (value: unknown): boolean => value === undefined;
  switch (binding.profile) {
    case PROFILE_REQUEST:
      if (!absent(binding.content_commitment) || !absent(binding.channel_binding) || !absent(binding.interval_index)) {
        throw new AssertionError("invalid");
      }
      if (
        typeof binding.request_action !== "string" || !includes(REQUEST_ACTIONS, binding.request_action) ||
        typeof binding.endpoint_class !== "string" || !includes(ENDPOINT_CLASSES, binding.endpoint_class)
      ) {
        throw new AssertionError("invalid");
      }
      return;
    case PROFILE_CONTENT:
      if (!absent(binding.request_action) || !absent(binding.endpoint_class) || !absent(binding.channel_binding) || !absent(binding.interval_index)) {
        throw new AssertionError("invalid");
      }
      if (typeof binding.content_commitment !== "string" || binding.content_commitment.length !== 43 || !isBase64Url(binding.content_commitment)) {
        throw new AssertionError("invalid");
      }
      return;
    case PROFILE_CHANNEL:
      if (!absent(binding.request_action) || !absent(binding.endpoint_class) || !absent(binding.content_commitment)) {
        throw new AssertionError("invalid");
      }
      if (typeof binding.channel_binding !== "string" || binding.channel_binding.length !== 43 || !isBase64Url(binding.channel_binding)) {
        throw new AssertionError("invalid");
      }
      if (
        typeof binding.interval_index !== "number" || !Number.isInteger(binding.interval_index) ||
        binding.interval_index < 0 || binding.interval_index > 4294967295
      ) {
        throw new AssertionError("invalid");
      }
      return;
    default:
      throw new AssertionError("invalid");
  }
}

// --- time ----------------------------------------------------------------

function canonicalTime(value: string): Date {
  if (!RFC3339_UTC.test(value)) {
    throw new AssertionError("invalid");
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().replace(/\.\d{3}Z$/, "Z") !== value) {
    throw new AssertionError("invalid");
  }
  return parsed;
}

function validityWindow(payload: Payload, now: Date): { issuedAt: Date; expiresAt: Date } {
  const issuedAt = canonicalTime(payload.issued_at);
  const expiresAt = canonicalTime(payload.expires_at);
  const lifetime = expiresAt.getTime() - issuedAt.getTime();
  if (lifetime <= 0 || lifetime > lifetimeFor(payload.binding.profile)) {
    throw new AssertionError("invalid");
  }
  if (issuedAt.getTime() > now.getTime() + MAXIMUM_CLOCK_SKEW_MS) {
    throw new AssertionError("invalid");
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw new AssertionError("expired");
  }
  return { issuedAt, expiresAt };
}

// --- canonical form ------------------------------------------------------

/**
 * Reproduces Go's json.Marshal of the Payload struct byte for byte: fields in
 * declaration order, no whitespace. Go additionally HTML-escapes < > and &,
 * which cannot occur here because every string has already passed a closed
 * vocabulary or pattern that excludes them; validation runs before this, in
 * both implementations, for exactly that reason.
 */
export function canonicalize(payload: Payload): Uint8Array {
  const string = (value: string): string => JSON.stringify(value);
  const list = (values: readonly string[]): string => `[${values.map(string).join(",")}]`;
  const canonical =
    `{"schema_version":${string(payload.schema_version)}` +
    `,"assurance_level":${payload.assurance_level}` +
    `,"assurance_sources":${list(payload.assurance_sources)}` +
    `,"reason_codes":${list(payload.reason_codes)}` +
    `,"uniqueness_scope":${string(payload.uniqueness_scope)}` +
    `,"agent_provenance":${string(payload.agent_provenance)}` +
    `,"binding":${canonicalBinding(payload.binding)}` +
    `,"policy_version":${string(payload.policy_version)}` +
    `,"model_version":${string(payload.model_version)}` +
    `,"issued_at":${string(payload.issued_at)}` +
    `,"expires_at":${string(payload.expires_at)}` +
    `,"nonce":${string(payload.nonce)}}`;
  return new TextEncoder().encode(canonical);
}

/**
 * Reproduces Go's json.Marshal of the Binding struct: fields in declaration
 * order, omitempty fields absent rather than null. The order is fixed by the
 * contract and shared with the Go implementation.
 */
function canonicalBinding(binding: Binding): string {
  const string = (value: string): string => JSON.stringify(value);
  const parts: string[] = [`"profile":${string(binding.profile)}`, `"session_binding":${string(binding.session_binding)}`];
  if (binding.request_action !== undefined) parts.push(`"request_action":${string(binding.request_action)}`);
  if (binding.endpoint_class !== undefined) parts.push(`"endpoint_class":${string(binding.endpoint_class)}`);
  if (binding.content_commitment !== undefined) parts.push(`"content_commitment":${string(binding.content_commitment)}`);
  if (binding.channel_binding !== undefined) parts.push(`"channel_binding":${string(binding.channel_binding)}`);
  if (binding.interval_index !== undefined) parts.push(`"interval_index":${binding.interval_index}`);
  parts.push(`"audience":${string(binding.audience)}`);
  return `{${parts.join(",")}}`;
}

// decodeBinding copies only the fields that are present. Under
// exactOptionalPropertyTypes an absent field must stay absent rather than be
// set to undefined, and the profile validation relies on that distinction.
function decodeBinding(object: Record<string, unknown>): Binding {
  const binding: {
    profile: string; session_binding: string; audience: string;
    request_action?: string; endpoint_class?: string; content_commitment?: string;
    channel_binding?: string; interval_index?: number;
  } = {
    profile: requireString(object["profile"]),
    session_binding: requireString(object["session_binding"]),
    audience: requireString(object["audience"]),
  };
  if (object["request_action"] !== undefined) binding.request_action = requireString(object["request_action"]);
  if (object["endpoint_class"] !== undefined) binding.endpoint_class = requireString(object["endpoint_class"]);
  if (object["content_commitment"] !== undefined) binding.content_commitment = requireString(object["content_commitment"]);
  if (object["channel_binding"] !== undefined) binding.channel_binding = requireString(object["channel_binding"]);
  if (object["interval_index"] !== undefined) {
    const interval = object["interval_index"];
    if (typeof interval !== "number") {
      throw new AssertionError("invalid");
    }
    binding.interval_index = interval;
  }
  return binding;
}

function signingMessage(canonical: Uint8Array): Uint8Array {
  const separator = new TextEncoder().encode(DOMAIN_SEPARATOR);
  const message = new Uint8Array(separator.length + canonical.length);
  message.set(separator, 0);
  message.set(canonical, separator.length);
  return message;
}

// --- encoding ------------------------------------------------------------

function isBase64Url(value: string): boolean {
  const decoded = decodeBase64Url(value);
  return decoded !== null && decoded.length > 0;
}

export function decodeBase64Url(value: string): Uint8Array | null {
  if (value.length === 0 || !BASE64URL.test(value) || value.length % 4 === 1) {
    return null;
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function includes(values: readonly string[], value: string): boolean {
  return values.includes(value);
}
