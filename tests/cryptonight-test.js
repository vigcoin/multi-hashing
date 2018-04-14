const { cryptonight } = require('../');
const { test } = require('./helper');

describe('cryptonight', () => {
    it('cryptonight', () => {
        test('cryptonight-slow.txt', (data) => cryptonight(data, false));
    });

    it('cryptonight fast', () => {
        test('cryptonight-fast.txt', (data) => cryptonight(data, true));
    });

    it('cryptonight v7', () => {
        test('cryptonight-slow-v7.txt', (data) => cryptonight(data, 1));
    });
});