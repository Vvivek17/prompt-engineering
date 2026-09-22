/**
 * SentinelScan - Automated Unit Test Suite
 * Component: 14-Day Federal Reserve Reg CC Banking Loophole
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../app.js');

describe('Banking Loophole & Reg CC Deficit Engine', () => {

  test('calculates net victim loss as full wire transfer out-of-pocket amount', () => {
    const deficit = engine.calculateBankingDeficit(4850, 4200);
    assert.equal(deficit.checkAmount, 4850);
    assert.equal(deficit.wireAmount, 4200);
    assert.equal(deficit.netLoss, -4200);
    assert.equal(deficit.retainedBonus, 650);
    assert.equal(deficit.debtString, '-$4,200.00 (DEBT)');
  });

  test('applies standard 85% equipment wire ratio when wire amount is omitted', () => {
    const deficit = engine.calculateBankingDeficit(5000);
    assert.equal(deficit.checkAmount, 5000);
    assert.equal(deficit.wireAmount, 4250); // 85% of 5000
    assert.equal(deficit.netLoss, -4250);
    assert.equal(deficit.retainedBonus, 750);
  });

  test('handles string inputs formatted with currency symbols and commas', () => {
    const deficit = engine.calculateBankingDeficit('$3,500.00', '$3,000.00');
    assert.equal(deficit.checkAmount, 3500);
    assert.equal(deficit.wireAmount, 3000);
    assert.equal(deficit.netLoss, -3000);
  });

  test('includes statutory citation for Federal Reserve Regulation CC', () => {
    const deficit = engine.calculateBankingDeficit(4850, 4200);
    assert.match(deficit.regCCCitation, /12 CFR Part 229/);
  });

  test('preserves non-negative retained bonus invariant', () => {
    const deficit = engine.calculateBankingDeficit(2000, 2500);
    assert.equal(deficit.retainedBonus, 0);
    assert.equal(deficit.netLoss, -2500);
  });

});
