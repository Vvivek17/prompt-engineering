/**
 * SentinelScan - Automated Unit Test Suite
 * Component: Psychological Manipulation & Social Engineering Profiler
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../app.js');

describe('Psychological Profiler & Manipulation Vectors', () => {

  test('quantifies artificial urgency and short deadline clocks', () => {
    const profile = engine.profilePsychology('Offer expires within 24 hours. Act fast to secure position.');
    assert.ok(profile.urgency >= 80, `Expected urgency >= 80, got ${profile.urgency}`);
  });

  test('quantifies religious and moral piety exploitation in rental scams', () => {
    const profile = engine.profilePsychology('I am a God-fearing missionary and pastor called away on humanitarian work with the United Nations.');
    assert.ok(profile.moral >= 90, `Expected moral score >= 90, got ${profile.moral}`);
  });

  test('quantifies unmonitored communication isolation channels (Telegram/Signal/WhatsApp)', () => {
    const profile = engine.profilePsychology('Message supervisor on Telegram handle @RecruiterDirect or WhatsApp');
    assert.ok(profile.isolation >= 90, `Expected isolation score >= 90, got ${profile.isolation}`);
  });

  test('quantifies inflated salary and financial bait vectors', () => {
    const profile = engine.profilePsychology('Earn $75.00 per hour for data transcription from home. Earn 500 USDT daily.');
    assert.ok(profile.bait >= 80, `Expected bait score >= 80, got ${profile.bait}`);
  });

  test('classifies Advance-Fee Procurement Syndicate archetype correctly', () => {
    const preset = engine.PRESETS.amazon_equipment;
    const profile = engine.profilePsychology(preset.text);
    assert.equal(profile.archetype.title, '🎭 Advance-Fee Procurement Syndicate');
    assert.ok(profile.archetype.tags.includes('#CheckOverpayment'));
  });

  test('classifies Absentee Faith-Based Rental Trap archetype correctly', () => {
    const preset = engine.PRESETS.rental_deposit;
    const profile = engine.profilePsychology(preset.text);
    assert.equal(profile.archetype.title, '⛪ Absentee Faith-Based Rental Trap');
    assert.ok(profile.archetype.tags.includes('#AbsenteeLandlord'));
  });

  test('classifies verified enterprise baseline when no manipulation vectors exist', () => {
    const preset = engine.PRESETS.legitimate_microsoft;
    const profile = engine.profilePsychology(preset.text);
    assert.equal(profile.archetype.title, '🛡️ Verified Enterprise Baseline');
    assert.ok(profile.archetype.tags.includes('#EnterpriseVetted'));
  });

});
