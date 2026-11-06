// One-time pad (modulo 37) en HMAC-SHA256, volledig in de browser.
// Het bericht en de sleutels verlaten de browser nooit: enkel ciphertext, lijnnummer en MAC gaan naar de server.

export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'; // A=0 ... Z=25, 0=26 ... 9=35, _=36
const MOD = ALPHABET.length; // 37
const encoder = new TextEncoder();

export class IntegrityError extends Error {}

function requireWebCrypto() {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
        throw new Error('Web Crypto is niet beschikbaar. Open de app via HTTPS of via http://localhost.');
    }
}

// Kleine letters worden hoofdletters, een spatie wordt _. Alle andere tekens weigeren we met een duidelijke fout.
export function normalize(text) {
    const result = text.toUpperCase().replaceAll(' ', '_');
    const bad = [...new Set([...result].filter(c => !ALPHABET.includes(c)))];
    if (bad.length > 0) {
        throw new Error('Niet toegelaten tekens: ' + bad.map(c => JSON.stringify(c)).join(' ') +
            '. Enkel A-Z, 0-9 en spatie zijn toegelaten.');
    }
    return result;
}

// direction +1 = versleutelen (optellen), -1 = ontsleutelen (aftrekken)
function shift(text, key, direction) {
    if (key.length < text.length) {
        throw new Error(`De sleutel is te kort: ${key.length} tekens voor een tekst van ${text.length} tekens. ` +
            'Een sleutel mag nooit hergebruikt of herhaald worden.');
    }
    let out = '';
    for (let i = 0; i < text.length; i++) {
        const t = ALPHABET.indexOf(text[i]);
        const k = ALPHABET.indexOf(key[i]);
        out += ALPHABET[(t + direction * k + MOD) % MOD];
    }
    return out;
}

export const otpEncrypt = (plain, key) => shift(normalize(plain), normalize(key.trim()), +1);
export const otpDecrypt = (cipher, key) => shift(normalize(cipher), normalize(key.trim()), -1);

// ---------------------------------------------------------------- HMAC

function toHex(buffer) {
    return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
        return null;
    }
    return Uint8Array.from(hex.match(/../g) || [], h => parseInt(h, 16));
}

async function importHmacKey(secret, usage) {
    requireWebCrypto();
    return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
}

// De MAC dekt de ciphertext en het lijnnummer, zodat ook het lijnnummer niet ongemerkt aangepast kan worden.
const macInput = (line, ciphertext) => encoder.encode(`${line}|${ciphertext}`);

export async function computeMac(secret, line, ciphertext) {
    const key = await importHmacKey(secret, 'sign');
    return toHex(await crypto.subtle.sign('HMAC', key, macInput(line, ciphertext)));
}

// crypto.subtle.verify vergelijkt in constante tijd, een gewone === niet.
export async function checkMac(secret, line, ciphertext, macHex) {
    const mac = fromHex(macHex);
    if (!mac) {
        return false;
    }
    const key = await importHmacKey(secret, 'verify');
    return crypto.subtle.verify('HMAC', key, mac, macInput(line, ciphertext));
}

// ---------------------------------------------------------------- bericht inpakken en uitpakken

// Dit is wat in de databank terechtkomt (kolom Body): enkel ciphertext, lijnnummer en MAC.
export async function sealMessage({ message, key, line, hmacSecret }) {
    if (!hmacSecret) {
        throw new Error('Geef een HMAC-sleutel in.');
    }
    const ct = otpEncrypt(message, key);
    const mac = await computeMac(hmacSecret, line, ct);
    return JSON.stringify({ v: 1, line, ct, mac });
}

export function parsePayload(body) {
    try {
        const p = JSON.parse(body);
        if (p && p.v === 1 && Number.isInteger(p.line) && typeof p.ct === 'string' && typeof p.mac === 'string') {
            return p;
        }
    } catch { /* geen versleuteld bericht */ }
    return null;
}

// Eerst de MAC controleren, pas daarna ontsleutelen.
export async function openMessage({ payload, key, hmacSecret }) {
    if (!(await checkMac(hmacSecret, payload.line, payload.ct, payload.mac))) {
        throw new IntegrityError('Waarschuwing: dit bericht is gewijzigd of de HMAC-sleutel klopt niet. Het bericht wordt niet getoond.');
    }
    return otpDecrypt(payload.ct, key).replaceAll('_', ' ');
}
