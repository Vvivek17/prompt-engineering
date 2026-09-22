/**
 * SentinelScan - Automated Unit Test Suite
 * Component: Tactical Counter-Interrogation Script Generator
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../app.js');

describe('Tactical Counter-Interrogation Generator', () => {

  test('generates employment fraud counter-interrogation with EIN demand', () => {
    const analysis = engine.analyzeOffer(
      engine.PRESETS.amazon_equipment.text,
      engine.PRESETS.amazon_equipment.senderEmail,
      engine.PRESETS.amazon_equipment.offerUrl
    );
    const script = engine.generateCounterInterrogation(analysis);

    assert.match(script, /CORPORATE EMPLOYMENT FRAUD TRAP/i);
    assert.match(script, /CORPORATE EIN & REGISTRATION/i);
    assert.match(script, /DIRECT SWITCHBOARD EXTENSION/i);
    assert.match(script, /DIRECT EQUIPMENT SHIPMENT/i);
  });

  test('generates rental trap counter-interrogation with County Assessor APN demand', () => {
    const analysis = engine.analyzeOffer(
      engine.PRESETS.rental_deposit.text,
      engine.PRESETS.rental_deposit.senderEmail,
      engine.PRESETS.rental_deposit.offerUrl
    );
    const script = engine.generateCounterInterrogation(analysis);

    assert.match(script, /ABSENTEE RENTAL TRAP/i);
    assert.match(script, /COUNTY ASSESSOR PARCEL IDENTIFIER/i);
    assert.match(script, /IN-PERSON WALK-THROUGH/i);
    assert.match(script, /LICENSED ESCROW DEPOSIT/i);
  });

  test('generates professional confirmation reply for verified legitimate offer', () => {
    const analysis = engine.analyzeOffer(
      engine.PRESETS.legitimate_microsoft.text,
      engine.PRESETS.legitimate_microsoft.senderEmail,
      engine.PRESETS.legitimate_microsoft.offerUrl
    );
    const script = engine.generateCounterInterrogation(analysis);

    assert.match(script, /OFFICIAL CANDIDATE CONFIRMATION/i);
    assert.match(script, /careers\.microsoft\.com/i);
    assert.doesNotMatch(script, /COUNTER-INTERROGATION/i);
  });

});
