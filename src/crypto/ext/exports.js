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