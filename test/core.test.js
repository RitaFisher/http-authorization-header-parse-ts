import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseAuthorizationHeader,
  parseAuthParams,
  decodeToken68,
} from '../src/index.js';

test('parseAuthorizationHeader splits scheme and credentials', () => {
  const result = parseAuthorizationHeader('Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==');
  assert.deepEqual(result, {
    scheme: 'basic',
    credentials: 'QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
  });
});

test('parseAuthorizationHeader lowercases the scheme', () => {
  const result = parseAuthorizationHeader('Bearer abc.def.ghi');
  assert.equal(result.scheme, 'bearer');
  assert.equal(result.credentials, 'abc.def.ghi');
});

test('parseAuthorizationHeader tolerates surrounding and internal whitespace', () => {
  const result = parseAuthorizationHeader('  Digest   username="u", realm="r"  ');
  assert.equal(result.scheme, 'digest');
  assert.equal(result.credentials, 'username="u", realm="r"');
});

test('parseAuthorizationHeader rejects an empty header', () => {
  assert.throws(() => parseAuthorizationHeader(''), /empty authorization header/);
  assert.throws(() => parseAuthorizationHeader('   '), /empty authorization header/);
});

test('parseAuthorizationHeader rejects a header with no credentials', () => {
  assert.throws(() => parseAuthorizationHeader('Basic'), /missing credentials after scheme/);
  assert.throws(() => parseAuthorizationHeader('Basic   '), /missing credentials after scheme/);
});

test('parseAuthorizationHeader rejects an invalid scheme token', () => {
  assert.throws(() => parseAuthorizationHeader('Ba(sic) xyz'), /invalid scheme/);
});

test('parseAuthParams reads simple token parameters', () => {
  const params = parseAuthParams('username=alice, realm=example');
  assert.deepEqual(params, [
    { key: 'username', value: 'alice' },
    { key: 'realm', value: 'example' },
  ]);
});

test('parseAuthParams preserves commas and equals inside quoted strings', () => {
  const params = parseAuthParams('username="a,b=c", realm="r"');
  assert.deepEqual(params, [
    { key: 'username', value: 'a,b=c' },
    { key: 'realm', value: 'r' },
  ]);
});

test('parseAuthParams honours backslash escapes in quoted strings', () => {
  const params = parseAuthParams('username="a\\"b", realm="r"');
  assert.deepEqual(params, [
    { key: 'username', value: 'a"b' },
    { key: 'realm', value: 'r' },
  ]);
});

test('parseAuthParams keeps duplicate keys in order', () => {
  const params = parseAuthParams('a=1, a=2, b=3');
  assert.deepEqual(params, [
    { key: 'a', value: '1' },
    { key: 'a', value: '2' },
    { key: 'b', value: '3' },
  ]);
});

test('parseAuthParams rejects malformed input', () => {
  assert.throws(() => parseAuthParams('username'), /missing '=' after parameter key/);
  assert.throws(() => parseAuthParams('username="unterminated'), /unterminated quoted string/);
  assert.throws(() => parseAuthParams('=value'), /empty parameter key/);
});

test('decodeToken68 decodes standard base64', () => {
  assert.equal(decodeToken68('QWxhZGRpbjpvcGVuIHNlc2FtZQ=='), 'Aladdin:open sesame');
});

test('decodeToken68 accepts base64url alphabet and missing padding', () => {
  // `-` and `_` are the base64url replacements for `+` and `/`.
  assert.equal(decodeToken68('PDw_Pz8-Pg'), '<<???>>');
});

test('decodeToken68 rejects non-base64 input', () => {
  assert.throws(() => decodeToken68('not base64!'), /not valid base64/);
  assert.throws(() => decodeToken68('A'), /invalid base64 length/);
});
