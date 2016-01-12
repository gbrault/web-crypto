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
      true, 
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
};

/**
 * Generates a digest from the hash function and data given as parameters.
 * 
 * @private
 * @param {string} hashAlg The name of the hash function to use.
 * @param {string|BufferSource} data The data to be hashed.
 * @returns {Promise} A Promise that returns the hash as ByteArray.
 */
function digest_sha_bytes(hashAlg, data) {
  return new Promise(function(resolve, reject) {
    if(isString(data)) {
      data = stringToBytes(data);
    };
    digest({name: hashAlg}, data).then(function(hash) {
      resolve(new Uint8Array(hash));
    }).catch(function(err) {
      reject(err);
    });
  });
};

/**
 * Generates the SHA-256 hash for the data given as parameter and retuns
 * the result as string in Base64URL format.
 * 
 * @memberOf module:webcrypto.ext.sha256
 * @alias base64URL
 * @param {string|BufferSource} data The data to be hashed.
 * @returns {Promise} A Promise that returns the hash as string in Base64URL 
 * format.
 */
function digest_sha256_base64URL(data) {
  return digest_sha_bytes('SHA-256', data).then(function(hash) {
    return bytesToBase64URL(hash);
  });
};

/**
 * Generates the SHA-256 hash for the data given as parameter and retuns
 * the result as string in hexadecimal format.
 * 
 * @memberOf module:webcrypto.ext.sha256
 * @alias hex
 * @param {string|BufferSource} data The data to be hashed.
 * @returns {Promise} A Promise that returns the hash as string in hexadecimal 
 * format.
 */
function digest_sha256_hex(data) {
  return digest_sha_bytes('SHA-256', data).then(function(hash) {
    return bytesToHex(hash);
  });
};