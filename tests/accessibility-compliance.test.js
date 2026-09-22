/**
 * SentinelScan - Automated Unit Test Suite
 * Component: WCAG 2.1 AA Accessibility & Semantic Architecture Compliance
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

describe('WCAG 2.1 AA Accessibility & Semantic Markup Compliance', () => {

  const htmlPath = path.join(__dirname, '..', 'index.html');
  const cssPath = path.join(__dirname, '..', 'style.css');

  const htmlContent = fs.readFileSync(htmlPath, 'utf8');
  const cssContent = fs.readFileSync(cssPath, 'utf8');

  test('contains skip to main content link for keyboard-only navigation', () => {
    assert.match(htmlContent, /class=["'][^"']*skip-link[^"']*["']/i);
    assert.match(htmlContent, /href=["']#main-content["']/i);
  });

  test('defines semantic landmark roles (banner, main, contentinfo, region)', () => {
    assert.match(htmlContent, /<header[^>]+role=["']banner["']/i);
    assert.match(htmlContent, /id=["']main-content["'][^>]+role=["']main["']/i);
    assert.match(htmlContent, /role=["']region["']/i);
  });

  test('ensures form controls have associated accessible labels', () => {
    assert.match(htmlContent, /<label[^>]+for=["']offerTextInput["']/i);
    assert.match(htmlContent, /<label[^>]+for=["']senderEmailInput["']/i);
    assert.match(htmlContent, /<label[^>]+for=["']offerUrlInput["']/i);
  });

  test('ensures threat gauge and progress bars have ARIA progressbar attributes', () => {
    assert.match(htmlContent, /role=["']progressbar["']/i);
    assert.match(htmlContent, /aria-valuenow/i);
    assert.match(htmlContent, /aria-valuemin=["']0["']/i);
    assert.match(htmlContent, /aria-valuemax=["']100["']/i);
  });

  test('ensures dynamic score regions declare aria-live announcements', () => {
    assert.match(htmlContent, /aria-live=["']polite["']/i);
  });

  test('ensures modal dialogs comply with WAI-ARIA modal specifications', () => {
    assert.match(htmlContent, /role=["']dialog["']/i);
    assert.match(htmlContent, /aria-modal=["']true["']/i);
  });

  test('ensures canvas radar has accessible role and text description', () => {
    assert.match(htmlContent, /<canvas[^>]+role=["']img["']/i);
    assert.match(htmlContent, /<canvas[^>]+aria-label=/i);
  });

  test('style.css implements prefers-reduced-motion media query', () => {
    assert.match(cssContent, /@media\s*\(prefers-reduced-motion:\s*reduce\)/i);
  });

  test('style.css implements visible keyboard focus indicators', () => {
    assert.match(cssContent, /:focus-visible/i);
  });

});
