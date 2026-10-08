const test = require('node:test');
const assert = require('node:assert');
const { SBOX, buildSteps } = require('../js/aes.js');

const hex = a => a.map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => h.match(/../g).map(x => parseInt(x, 16));
const fromText = s => [...Buffer.from(s)];

test('S-box matches known entries', () => {
  assert.strictEqual(SBOX[0x00], 0x63);
  assert.strictEqual(SBOX[0x53], 0xed);
  assert.strictEqual(SBOX[0xff], 0x16);
});

test('FIPS-197 Appendix B vector', () => {
  const { steps } = buildSteps(
    fromHex('3243f6a8885a308d313198a2e0370734'),
    fromHex('2b7e151628aed2a6abf7158809cf4f3c'));
  assert.strictEqual(hex(steps.at(-1).after), '3925841d02dc09fbdc118597196a0b32');
  // state after the initial AddRoundKey
  assert.strictEqual(hex(steps[1].after), '193de3bea0f4e22b9ac68d2ae9f84808');
});

test('FIPS-197 Appendix C.1 vector', () => {
  const { steps } = buildSteps(
    fromHex('00112233445566778899aabbccddeeff'),
    fromHex('000102030405060708090a0b0c0d0e0f'));
  assert.strictEqual(hex(steps.at(-1).after), '69c4e0d86a7b0430d8cdb78070b4c55a');
});

test('"Two One Nine Two" example', () => {
  const { steps } = buildSteps(fromText('Two One Nine Two'), fromText('Thats my Kung Fu'));
  assert.strictEqual(hex(steps.at(-1).after), '29c3505f571420f6402299b31a02d73a');
});

test('step count: load + round 0 + 9 full rounds + final round', () => {
  const { steps } = buildSteps(new Array(16).fill(0), new Array(16).fill(0));
  assert.strictEqual(steps.length, 1 + 1 + 9 * 4 + 3);
});
