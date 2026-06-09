// AWS SigV4 — minimum surface needed for R2's S3-compatible API.
//
// Two entry points:
//   `signedFetch(opts)` — sign a one-off request (used for LIST and DELETE
//   object ops the server makes on the customer's behalf).
//   `presignUrl(opts)` — produce a presigned URL the browser can hit directly
//   (used for PUT uploads and GET downloads — Pattern 3 from the brief).
//
// Implemented in pure JS against WebCrypto; no aws-sdk dep (~700 KB saved).
// Spec: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
//
// R2 specifics: region = "auto", service = "s3", host =
// "<accountId>.r2.cloudflarestorage.com". UNSIGNED-PAYLOAD is acceptable for
// PUT/GET object presigning (R2 doesn't require streaming SHA256 over the
// body) so the browser doesn't have to pre-hash large uploads.

export type R2Creds = {
  accessKeyId: string;
  secretAccessKey: string;
  accountId: string;
};

const REGION = 'auto';
const SERVICE = 's3';
const ALGO = 'AWS4-HMAC-SHA256';

export function r2Host(accountId: string): string {
  return `${accountId}.r2.cloudflarestorage.com`;
}

export function r2Endpoint(accountId: string): string {
  return `https://${r2Host(accountId)}`;
}

// ---- low-level crypto ---------------------------------------------------

const enc = new TextEncoder();

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  return toHex(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

async function hmac(
  key: ArrayBuffer | Uint8Array,
  data: string | Uint8Array
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  const sig = await crypto.subtle.sign('HMAC', k, bytes as BufferSource);
  return new Uint8Array(sig);
}

async function signingKey(
  secret: string,
  dateStamp: string
): Promise<Uint8Array> {
  const kDate = await hmac(enc.encode('AWS4' + secret), dateStamp);
  const kRegion = await hmac(kDate, REGION);
  const kService = await hmac(kRegion, SERVICE);
  return await hmac(kService, 'aws4_request');
}

// S3 percent-encoding for keys/paths. RFC3986 unreserved set + '/' kept as-is.
// AWS treats '/' as a path separator and does NOT encode it inside the
// CanonicalURI when present in object keys.
function encodeKey(key: string): string {
  return key
    .split('/')
    .map((seg) =>
      encodeURIComponent(seg).replace(
        /[!'()*]/g,
        (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
      )
    )
    .join('/');
}

// Query-string encoding for canonical request. AWS quirk: encode space as
// %20 (not '+'), encode the full RFC3986 unreserved set.
function encodeQueryComponent(s: string): string {
  return encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function amzDate(d: Date): { stamp: string; full: string } {
  const iso = d.toISOString().replace(/[-:]|\.\d{3}/g, '');
  return { stamp: iso.slice(0, 8), full: iso };
}

// ---- presigned URL ------------------------------------------------------

export type PresignOpts = {
  creds: R2Creds;
  method: 'GET' | 'PUT' | 'DELETE';
  bucket: string;
  key: string;
  expiresIn: number; // seconds, max 604800 (7 days)
  /** Extra signed headers (e.g. content-type for PUT). The browser MUST send these on the request. */
  signedHeaders?: Record<string, string>;
};

export async function presignUrl(opts: PresignOpts): Promise<string> {
  const { creds, method, bucket, key, expiresIn } = opts;
  if (expiresIn < 1 || expiresIn > 604800) {
    throw new Error('expiresIn must be between 1 and 604800 seconds');
  }
  const host = r2Host(creds.accountId);
  const now = new Date();
  const { stamp, full } = amzDate(now);
  const scope = `${stamp}/${REGION}/${SERVICE}/aws4_request`;
  const credential = `${creds.accessKeyId}/${scope}`;

  // Always sign the host header. If the caller declared extra signed
  // headers, fold them in (lower-case names, trimmed values).
  const hdrs: Record<string, string> = { host };
  for (const [k, v] of Object.entries(opts.signedHeaders ?? {})) {
    hdrs[k.toLowerCase()] = v.trim().replace(/\s+/g, ' ');
  }
  const sortedHdrNames = Object.keys(hdrs).sort();
  const canonicalHeaders =
    sortedHdrNames.map((n) => `${n}:${hdrs[n]}`).join('\n') + '\n';
  const signedHeaderList = sortedHdrNames.join(';');

  // Query params go into the canonical request in lexicographic order, each
  // value URI-encoded once.
  const qs: Record<string, string> = {
    'X-Amz-Algorithm': ALGO,
    'X-Amz-Credential': credential,
    'X-Amz-Date': full,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': signedHeaderList,
  };

  const canonicalQueryString = Object.keys(qs)
    .sort()
    .map((k) => `${encodeQueryComponent(k)}=${encodeQueryComponent(qs[k])}`)
    .join('&');

  const canonicalUri = `/${encodeKey(bucket)}/${encodeKey(key)}`;
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaderList,
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    ALGO,
    full,
    scope,
    await sha256Hex(canonicalRequest),
  ].join('\n');

  const sigKey = await signingKey(creds.secretAccessKey, stamp);
  const signature = toHex(await hmac(sigKey, stringToSign));

  return `https://${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

// ---- one-shot signed request -------------------------------------------

export type SignedRequestOpts = {
  creds: R2Creds;
  method: 'GET' | 'PUT' | 'DELETE' | 'POST';
  path: string; // starts with '/', already key-encoded if it includes user input
  query?: Record<string, string>;
  body?: string | Uint8Array;
  extraHeaders?: Record<string, string>;
};

export async function signedFetch(
  opts: SignedRequestOpts
): Promise<Response> {
  const { creds, method, path } = opts;
  const host = r2Host(creds.accountId);
  const now = new Date();
  const { stamp, full } = amzDate(now);
  const scope = `${stamp}/${REGION}/${SERVICE}/aws4_request`;

  // Build canonical query string from a sorted dict; lets callers pass
  // params without worrying about ordering.
  const queryEntries = Object.entries(opts.query ?? {}).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0
  );
  const canonicalQueryString = queryEntries
    .map(([k, v]) => `${encodeQueryComponent(k)}=${encodeQueryComponent(v)}`)
    .join('&');

  const body = opts.body ?? '';
  const bodyBytes = typeof body === 'string' ? enc.encode(body) : body;
  const payloadHash = await sha256Hex(bodyBytes);

  const headers: Record<string, string> = {
    host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': full,
    ...Object.fromEntries(
      Object.entries(opts.extraHeaders ?? {}).map(([k, v]) => [
        k.toLowerCase(),
        v,
      ])
    ),
  };

  const sortedHdrNames = Object.keys(headers).sort();
  const canonicalHeaders =
    sortedHdrNames
      .map((n) => `${n}:${headers[n].trim().replace(/\s+/g, ' ')}`)
      .join('\n') + '\n';
  const signedHeaderList = sortedHdrNames.join(';');

  const canonicalRequest = [
    method,
    path,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaderList,
    payloadHash,
  ].join('\n');

  const stringToSign = [
    ALGO,
    full,
    scope,
    await sha256Hex(canonicalRequest),
  ].join('\n');

  const sigKey = await signingKey(creds.secretAccessKey, stamp);
  const signature = toHex(await hmac(sigKey, stringToSign));

  const authz = `${ALGO} Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaderList}, Signature=${signature}`;

  const url = `https://${host}${path}${canonicalQueryString ? '?' + canonicalQueryString : ''}`;
  // host is REQUIRED in the SigV4 canonical headers (signed above), but on
  // the wire it MUST NOT be explicitly set in fetch() headers. The Workers
  // runtime treats Host as a forbidden header — passing it either gets
  // stripped or duplicated depending on runtime, breaking R2's signature
  // reconstruction. R2 always sees the URL-derived Host, which matches
  // what we signed.
  const { host: _omit, ...fetchHeaders } = headers;
  void _omit;
  return fetch(url, {
    method,
    headers: { ...fetchHeaders, Authorization: authz },
    body: method === 'GET' || method === 'DELETE' ? undefined : (bodyBytes as BodyInit),
  });
}
