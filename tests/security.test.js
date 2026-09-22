/**
 * SentinelScan - Automated Unit Test Suite
 * Component: Security Defenses, XSS Sanitization & Cryptographic Digest
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../app.js');

describe('Security Defenses, Sanitization & Cryptography', () => {

  describe('XSS Sanitization & HTML Escaping', () => {
    test('escapes HTML special characters to prevent script injection', () => {
      const malicious = '<script>alert("xss")</script>';
      const escaped = engine.escapeHTML(malicious);
      assert.equal(escaped, '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      assert.doesNotMatch(escaped, /<script>/);
    });

    test('escapes image onerror payloads and single quotes', () => {
      const malicious = '<img src=x onerror=\'stealCookies()\'>';
      const escaped = engine.escapeHTML(malicious);
      assert.match(escaped, /&lt;img/);
      assert.match(escaped, /&#039;/);
    });

    test('escapes ampersands and attribute closures safely', () => {
      const raw = 'Tech Corp & Associates > "Leading Partners"';
      const escaped = engine.escapeHTML(raw);
      assert.equal(escaped, 'Tech Corp &amp; Associates &gt; &quot;Leading Partners&quot;');
    });
  });

  describe('Cryptographic Audit Digest', () => {
    test('generates valid 64-character hexadecimal digest', () => {
      const digest = engine.simulateSHA256('Employment Offer Contract Text 2026');
      assert.equal(typeof digest, 'string');
      assert.equal(digest.length, 64);
      assert.match(digest, /^[0-9a-f]{64}$/i);
    });

    test('deterministic output for identical contract input', () => {
      const input = 'Amazon Logistics Coordinator Offer Reference #8892';
      const digest1 = engine.simulateSHA256(input);
      const digest2 = engine.simulateSHA256(input);
      assert.equal(digest1, digest2);
    });

    test('distinct digests for modified contract inputs (avoids collision)', () => {
      const digest1 = engine.simulateSHA256('Contract Version A');
      const digest2 = engine.simulateSHA256('Contract Version B');
      assert.notEqual(digest1, digest2);
    });
  });

});
