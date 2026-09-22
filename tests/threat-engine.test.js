/**
 * SentinelScan - Automated Unit Test Suite
 * Component: Core Threat Engine & Domain Intelligence
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../app.js');

describe('Core Threat Engine & Domain Intelligence', () => {

  describe('Levenshtein Distance Calculations', () => {
    test('returns 0 for identical strings', () => {
      assert.equal(engine.levenshteinDistance('amazon', 'amazon'), 0);
      assert.equal(engine.levenshteinDistance('MICROSOFT', 'microsoft'), 0);
    });

    test('returns correct distance for single character replacement', () => {
      assert.equal(engine.levenshteinDistance('amaz0n', 'amazon'), 1);
      assert.equal(engine.levenshteinDistance('g00gle', 'google'), 2);
    });

    test('returns correct distance for single character insertion or deletion', () => {
      assert.equal(engine.levenshteinDistance('amazonn', 'amazon'), 1);
      assert.equal(engine.levenshteinDistance('amazn', 'amazon'), 1);
    });

    test('handles empty or falsy strings gracefully', () => {
      assert.equal(engine.levenshteinDistance('', 'amazon'), 6);
      assert.equal(engine.levenshteinDistance(null, 'google'), 6);
      assert.equal(engine.levenshteinDistance('', ''), 0);
    });
  });

  describe('Domain Extraction & Intelligence', () => {
    test('extracts clean hostname from URL with protocol, port, and query parameters', () => {
      assert.equal(engine.extractDomain('https://careers-portal.xyz:8080/apply?ref=12'), 'careers-portal.xyz');
      assert.equal(engine.extractDomain('http://login.subdomain.co.uk/auth'), 'login.subdomain.co.uk');
    });

    test('extracts domain from email address', () => {
      assert.equal(engine.extractDomain('recruiter@google-jobs.top'), 'google-jobs.top');
      assert.equal(engine.extractDomain('hr-officer@amazon.com'), 'amazon.com');
    });

    test('handles missing or malformed domain inputs gracefully', () => {
      assert.equal(engine.extractDomain(''), null);
      assert.equal(engine.extractDomain(null), null);
      const intel = engine.analyzeDomainIntel(null);
      assert.equal(intel.domain, 'N/A');
      assert.equal(intel.riskScore, 10);
    });

    test('correctly flags free mail providers for enterprise recruiting', () => {
      const providers = ['gmail.com', 'outlook.com', 'yahoo.com', 'proton.me'];
      for (const p of providers) {
        const intel = engine.analyzeDomainIntel(p);
        assert.equal(intel.isFreeMail, true, `Provider ${p} should be flagged as free mail`);
        assert.ok(intel.riskScore >= 30);
      }
    });

    test('flags suspicious top-level domains', () => {
      const suspiciousDomains = ['hiring-hub.xyz', 'operations-portal.top', 'task-work.buzz'];
      for (const d of suspiciousDomains) {
        const intel = engine.analyzeDomainIntel(d);
        assert.equal(intel.isSuspiciousTLD, true, `Domain ${d} should be flagged as suspicious TLD`);
      }
    });

    test('detects brand keyword and typo-spoofing', () => {
      const intel1 = engine.analyzeDomainIntel('amazon-operations-portal.xyz');
      assert.match(intel1.typoSquatRisk, /CRITICAL/i);
      assert.equal(intel1.similarityTarget, 'amazon');

      const intel2 = engine.analyzeDomainIntel('amaz0n.com');
      assert.ok(intel2.typoSquatRisk !== 'None');
    });
  });

  describe('Scam Classification & Heuristic Scoring', () => {
    test('classifies Amazon cashier check equipment trap as CRITICAL threat (>75)', () => {
      const preset = engine.PRESETS.amazon_equipment;
      const res = engine.analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl);

      assert.ok(res.threatIndex >= 75, `Expected threat index >= 75, got ${res.threatIndex}`);
      assert.equal(res.threatClass, 'danger');
      assert.ok(res.flags.some(f => f.ruleId === 'FIN_CASHIERS_CHECK'));
      assert.ok(res.flags.some(f => f.ruleId === 'FIN_EQUIPMENT_VENDOR'));
      assert.ok(res.flags.some(f => f.ruleId === 'CHAN_UNMONITORED_MESSENGER'));
    });

    test('classifies absentee rental deposit trap as CRITICAL threat (>75)', () => {
      const preset = engine.PRESETS.rental_deposit;
      const res = engine.analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl);

      assert.ok(res.threatIndex >= 75);
      assert.equal(res.threatClass, 'danger');
      assert.ok(res.flags.some(f => f.ruleId === 'FIN_RENTAL_DEPOSIT_BEFORE_VIEW'));
      assert.ok(res.flags.some(f => f.ruleId === 'FIN_UNTRACEABLE_PAYMENT'));
      assert.ok(res.flags.some(f => f.ruleId === 'LING_RELIGIOUS_MORAL_POSTURE'));
    });

    test('classifies legitimate enterprise offer as SAFE (<25)', () => {
      const preset = engine.PRESETS.legitimate_microsoft;
      const res = engine.analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl);

      assert.ok(res.threatIndex < 25, `Expected threat index < 25, got ${res.threatIndex}`);
      assert.equal(res.threatClass, 'safe');
      assert.equal(res.flags.length, 0);
    });

    test('sandbox overrides dynamically adjust threat parameters', () => {
      const preset = engine.PRESETS.amazon_equipment;

      // Override payment trap to false
      const modifiedRes = engine.analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl, {
        hasPaymentTrap: false,
        interviewChannel: 'corporate'
      });

      assert.ok(modifiedRes.scores.finance === 0);
      assert.ok(modifiedRes.threatIndex < preset.checkAmt);
    });
  });

});
