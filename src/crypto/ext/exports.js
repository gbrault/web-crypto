/**
 * The ext namespace contains functions which are not specified by the
 * W3C specification. They provide a simpler API for some use cases.
 * @memberOf module:webcrypto
 * @namespace ext
 */
exports.ext = {};

/**
 * The namespace pbkdf2 contains functions that are based on the 
 * PBKDF2 algorihtm.
 * 
 * @memberOf module:webcrypto.ext
 * @namespace pbkdf2
 */
exports.ext.pbkdf2 = {};
exports.ext.pbkdf2.deriveKeySha256 = deriveKey_pbkdf2_sha256;

/**
 * The namespace sha256 contains functions that are based on the
 * SHA-256 hash algorithm.
 * 
 * @memberOf module:webcrypto.ext
 * @namespace sha256
 */
exports.ext.sha256 = {};
exports.ext.sha256.base64URL = digest_sha256_base64URL;
exports.ext.sha256.hex = digest_sha256_hex;