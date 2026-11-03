# http-authorization-header-parse-ts

Decodes an HTTP `Authorization` header into its scheme token and the opaque credentials half, with helpers for the two common credential shapes.

```js
import {
  parseAuthorizationHeader,
  parseAuthParams,
  decodeToken68,
} from './src/index.js';

const { scheme, credentials } = parseAuthorizationHeader(
  'Digest username="alice", realm="example"'
);
// scheme === 'digest'
// credentials === 'username="alice", realm="example"'

parseAuthParams(credentials);
// [{ key: 'username', value: 'alice' }, { key: 'realm', value: 'example' }]

decodeToken68('QWxhZGRpbjpvcGVuIHNlc2FtZQ==');
// 'Aladdin:open sesame'
```

The package is ESM-only, has no dependencies, and runs on Node's standard library.

## Why this exists

The `Authorization` header is a scheme token followed by credentials, and the credentials are deliberately opaque to the HTTP layer: `Basic` uses base64, `Bearer` uses a token, `Digest` uses a comma-separated parameter list. A single parser that tried to understand all three would need a registry of schemes and would reject anything it had not been taught. The trade-off here is the opposite: `parseAuthorizationHeader` only splits scheme from credentials and validates the scheme as an RFC 7235 token. It never guesses at the credential format. Callers who know their scheme then call `parseAuthParams` or `decodeToken68` on the credentials string.

## The awkward edge

`parseAuthParams` is not a general CSV parser. It implements the `auth-param` grammar: keys are separated by commas, values are tokens or quoted-strings, and commas or equals signs inside quoted strings are preserved. A quoted string with an unterminated quote raises an error rather than silently consuming the rest of the input. Duplicate keys are returned in order instead of being collapsed, because different schemes disagree on whether the first or last duplicate is authoritative.
