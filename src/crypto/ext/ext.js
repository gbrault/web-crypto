/**
 * Derives a key from the given password and parameters using the
 * PBKDF2 with HMAC and SHA256. 
 * 
 * @memberOf module:webcrypto.ext.pbkdf2
 * @alias deriveKeySha256
 * @param {AlgorithmIdentifier} derivedKeyType The algorithm the derived key 
 * will be used for.
 * @param {boolean} extractable Indicating if the key can be extracted from the 
 * CryptoKey object at a later stage.
 * @param {string[]} keyUsages Indicating what can be done with the key.
 * @param {BufferSource|string} password The password from which the key is derived.
 * @param {BufferSource|string} salt The salt.
 * @param {number} iterations The number of iterations to derive the key.
 * @returns {Promise} Promise that returns the newly created CryptoKey.
 */
function deriveKey_pbkdf2_sha256(derivedKeyType, extractable, keyUsages, 
        password, salt, iterations) {
  return new Promise(function(resolve, reject) {
    
    if(isString(password)) {
      password = stringToBytes(password, true);
    }
    if(isString(salt)) {
      salt = stringToBytes(salt, true);
    }
    
    importKey(
      'raw', 
      password,
      {name: 'PBKDF2'}, 
      false, 
      ['deriveKey']
    ).then(function(baseKey) {
      return deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: iterations,
          hash: {name: 'SHA-256'}
        },
        baseKey,
        derivedKeyType,
        extractable,
        keyUsages);
    }).then(function(derivedKey) {
      resolve(derivedKey);
    }).catch(function(err) {
      reject(err);
    });
    
  });
}