/**
 * The subtle namespace contains the common cryptographic methods.<br />
 * It is the equivalent to the SubtleCrypto interface.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto}
 * @memberOf module:webcrypto
 * @namespace subtle
 */
exports.subtle = {};
exports.subtle.generateKey = generateKey;
exports.subtle.exportKey = exportKey;
exports.subtle.importKey = importKey;
exports.subtle.decrypt = decrypt;
exports.subtle.encrypt = encrypt;
exports.subtle.wrapKey = wrapKey;
exports.subtle.unwrapKey = unwrapKey;
exports.subtle.deriveBits = deriveBits;
exports.subtle.deriveKey = deriveKey;
exports.subtle.digest = digest;