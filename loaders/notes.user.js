// ==UserScript==
// @name         Test Support Tool - Notes (Loader)
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Scarica, decifra ed esegue "Test Support Tool - Notes"
// @match        https://*.force.com/*
// @match        https://*.salesforce.com/*
// @match        https://*.salesforce-setup.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=force.com
// @run-at       document-end
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_cookie
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @grant        unsafeWindow
// @connect      raw.githubusercontent.com
// @connect      my.salesforce.com
// @connect      salesforce.com
// @connect      force.com
// @updateURL    https://raw.githubusercontent.com/PellegrinoLuigi/FW_Tampermonkey_dist/main/loaders/notes.user.js
// @downloadURL  https://raw.githubusercontent.com/PellegrinoLuigi/FW_Tampermonkey_dist/main/loaders/notes.user.js
// ==/UserScript==

// Esegue il codice decifrato nello scope dello userscript (così vede GM_* e unsafeWindow).
// Definita fuori dall'IIFE del loader per non esporre le sue variabili locali.
function __tmRunPayload(__code) { eval(__code); }

(function () {
    'use strict';

    const ENC_URL   = "https://raw.githubusercontent.com/PellegrinoLuigi/FW_Tampermonkey_dist/main/notes.enc.json";
    const TOOL_NAME = "Test Support Tool - Notes";
    const PASS_KEY  = 'tm-loader-password';
    const KEY_CACHE = 'tm-loader-key';      // chiave AES derivata, per non rifare PBKDF2 a ogni pagina
    const ENC_CACHE = 'tm-loader-enc';      // ultima copia cifrata, usata se GitHub non risponde
    const META_KEY  = 'tm-loader-meta';     // @match/@exclude reali del tool (dall'ultima decifratura)
    const isTop = window.self === window.top;

    GM_registerMenuCommand('🔑 Imposta/Reimposta password', () => {
        const p = prompt('Password per ' + TOOL_NAME + ':');
        if (p) { GM_setValue(PASS_KEY, p); GM_setValue(KEY_CACHE, ''); location.reload(); }
    });

    // --- Match URL con i pattern reali del tool ---
    function globToRegex(glob) {
        return new RegExp('^' + glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
    }
    function urlAllowed(meta, url) {
        const inc = [...meta.match, ...meta.include];
        if (inc.length && !inc.some(g => globToRegex(g).test(url))) return false;
        return !meta.exclude.some(g => globToRegex(g).test(url));
    }
    function parseMeta(code) {
        const block = (code.match(/==UserScript==([\s\S]*?)==\/UserScript==/) || [])[1] || '';
        const values = (tag) => [...block.matchAll(new RegExp('@' + tag + '\\s+(\\S+)', 'g'))].map(m => m[1]);
        return { match: values('match'), include: values('include'), exclude: values('exclude') };
    }

    // --- Crittografia (WebCrypto) ---
    const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

    async function getKey(password, payload) {
        const cached = GM_getValue(KEY_CACHE, '');
        if (cached && cached.salt === payload.salt && cached.iter === payload.iter) {
            return crypto.subtle.importKey('raw', fromB64(cached.key), 'AES-GCM', false, ['decrypt']);
        }
        const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(payload.salt), iterations: payload.iter },
            baseKey, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
        const raw = await crypto.subtle.exportKey('raw', key);
        return { key, cacheEntry: { salt: payload.salt, iter: payload.iter, key: toB64(raw) } };
    }

    async function decrypt(payload, password) {
        const k = await getKey(password, payload);
        const key = k.key || k;
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(payload.iv) }, key, fromB64(payload.data));
        if (k.cacheEntry) GM_setValue(KEY_CACHE, k.cacheEntry);
        return new TextDecoder().decode(plain);
    }

    function fetchEnc() {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'GET',
                url: ENC_URL + '?t=' + Date.now(),
                timeout: 15000,
                onload: (r) => (r.status === 200 ? resolve(r.responseText) : reject(new Error('HTTP ' + r.status))),
                onerror: () => reject(new Error('errore di rete')),
                ontimeout: () => reject(new Error('timeout')),
            });
        });
    }

    async function main() {
        const meta = GM_getValue(META_KEY, null);
        if (meta && !urlAllowed(meta, location.href)) return;   // pagina non prevista: nessun download

        let password = GM_getValue(PASS_KEY, '');
        if (!password) {
            if (!isTop) return;
            password = prompt('Password per ' + TOOL_NAME + ' (richiesta una sola volta su questo PC):');
            if (!password) return;
        }

        let encText;
        try {
            encText = await fetchEnc();
            GM_setValue(ENC_CACHE, encText);
        } catch (e) {
            encText = GM_getValue(ENC_CACHE, '');
            console.warn('[' + TOOL_NAME + ' Loader] Download fallito (' + e.message + '), uso la copia locale.');
            if (!encText) return;
        }

        let code;
        try {
            code = await decrypt(JSON.parse(encText), password);
        } catch (e) {
            GM_setValue(PASS_KEY, '');
            GM_setValue(KEY_CACHE, '');
            if (isTop) alert(TOOL_NAME + ': password errata o file danneggiato. Ricarica la pagina per reinserirla.');
            return;
        }
        GM_setValue(PASS_KEY, password);

        const newMeta = parseMeta(code);
        GM_setValue(META_KEY, newMeta);
        if (!urlAllowed(newMeta, location.href)) return;

        __tmRunPayload(code);
    }

    main().catch(e => console.error('[' + TOOL_NAME + ' Loader]', e));
})();
