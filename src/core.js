const SCHEME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Split an HTTP Authorization header into its scheme and credentials.
 *
 * The credentials half is opaque: RFC 7235 defines it as `token68` or a
 * comma-separated list of `auth-param`s. We deliberately do not try to
 * parse the parameter list into a map here, because the scheme decides
 * whether the value is base64, a quoted string, or something else. Callers
 * that need structured parameters should use `parseAuthParams` on the
 * returned `credentials` string.
 *
 * @param {string} header
 * @returns {{scheme: string, credentials: string}}
 */
export function parseAuthorizationHeader(header) {
  if (typeof header !== 'string') {
    throw new TypeError('header must be a string');
  }

  const trimmed = header.trim();
  if (trimmed.length === 0) {
    throw new Error('empty authorization header');
  }

  // The scheme is a token, so it cannot contain whitespace. Find the first
  // run of non-whitespace characters and validate it as a token.
  let i = 0;
  while (i < trimmed.length && !isWhitespace(trimmed[i])) {
    i++;
  }

  const scheme = trimmed.slice(0, i);
  if (!SCHEME_RE.test(scheme)) {
    throw new Error(`invalid scheme: ${scheme}`);
  }

  // Skip exactly one run of whitespace between scheme and credentials.
  let j = i;
  while (j < trimmed.length && isWhitespace(trimmed[j])) {
    j++;
  }

  const credentials = trimmed.slice(j);
  if (credentials.length === 0) {
    throw new Error('missing credentials after scheme');
  }

  return { scheme: scheme.toLowerCase(), credentials };
}

/**
 * Parse the credentials half of an Authorization header into ordered
 * key/value pairs.
 *
 * This is the comma-separated `auth-param` grammar, not a general CSV
 * reader. Values may be tokens or quoted-strings; commas and equals signs
 * inside quoted strings are preserved. Duplicate keys are kept in order so
 * callers can decide which one wins.
 *
 * @param {string} credentials
 * @returns {Array<{key: string, value: string}>}
 */
export function parseAuthParams(credentials) {
  if (typeof credentials !== 'string') {
    throw new TypeError('credentials must be a string');
  }

  const params = [];
  let i = 0;

  while (i < credentials.length) {
    // Skip leading whitespace and commas between parameters.
    while (i < credentials.length && (isWhitespace(credentials[i]) || credentials[i] === ',')) {
      i++;
    }
    if (i >= credentials.length) {
      break;
    }

    // Read the key: everything up to '=' or a separator.
    const keyStart = i;
    while (i < credentials.length && credentials[i] !== '=' && credentials[i] !== ',' && !isWhitespace(credentials[i])) {
      i++;
    }
    const key = credentials.slice(keyStart, i);
    if (key.length === 0) {
      throw new Error(`empty parameter key at position ${keyStart}`);
    }

    // Skip whitespace before '='.
    while (i < credentials.length && isWhitespace(credentials[i])) {
      i++;
    }

    if (i >= credentials.length || credentials[i] !== '=') {
      throw new Error(`missing '=' after parameter key: ${key}`);
    }
    i++; // consume '='

    // Skip whitespace after '='.
    while (i < credentials.length && isWhitespace(credentials[i])) {
      i++;
    }

    let value;
    if (i < credentials.length && credentials[i] === '"') {
      // Quoted-string: read until the closing quote, honouring backslash
      // escapes so that `"` and `\\` survive.
      i++; // consume opening quote
      let out = '';
      let closed = false;
      while (i < credentials.length) {
        const ch = credentials[i];
        if (ch === '\\') {
          if (i + 1 >= credentials.length) {
            throw new Error('unterminated escape in quoted string');
          }
          out += credentials[i + 1];
          i += 2;
          continue;
        }
        if (ch === '"') {
          i++; // consume closing quote
          closed = true;
          break;
        }
        out += ch;
        i++;
      }
      if (!closed) {
        throw new Error('unterminated quoted string');
      }
      value = out;
    } else {
      // Token value: read until whitespace or comma.
      const valueStart = i;
      while (i < credentials.length && credentials[i] !== ',' && !isWhitespace(credentials[i])) {
        i++;
      }
      value = credentials.slice(valueStart, i);
      if (value.length === 0) {
        throw new Error(`empty value for parameter: ${key}`);
      }
    }

    params.push({ key, value });
  }

  return params;
}

/**
 * Decode the base64 payload of a `token68`-style Authorization header.
 *
 * `token68` is base64 with `-` and `_` allowed in place of `+` and `/`,
 * and optional trailing `=` padding. We strip padding before decoding
 * because the standard `atob`-style decoders reject unpadded input.
 *
 * @param {string} token
 * @returns {string}
 */
export function decodeToken68(token) {
  if (typeof token !== 'string') {
    throw new TypeError('token must be a string');
  }
  if (!/^[A-Za-z0-9+\-_/]+=*$/.test(token)) {
    throw new Error('token is not valid base64');
  }

  const normalized = token.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  // Pad to a multiple of 4 so the decoder accepts it. Lengths congruent
  // to 1 mod 4 are impossible in valid base64 and are rejected here.
  const remainder = normalized.length % 4;
  if (remainder === 1) {
    throw new Error('invalid base64 length');
  }
  const padded = normalized + '='.repeat((4 - remainder) % 4);

  // `Buffer` is the standard-library base64 decoder in Node and is
  // available without any import in ESM.
  const decoded = Buffer.from(padded, 'base64').toString('utf8');
  return decoded;
}

function isWhitespace(ch) {
  return ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n';
}
