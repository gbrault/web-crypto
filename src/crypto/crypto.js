
var isIE = !!global.msCrypto,
    isW3C = !!global.crypto,
    globalCrypto = global.crypto || global.msCrypto,
    subtle;
    
if(globalCrypto) subtle = globalCrypto.subtle;

/**
 * Creates a new CryptoKey object.
 * 
 * @memberOf module:webcrypto
 * @constructs CryptoKey
 * @param {string} type The type of the key. Possible values are "secret", 
 * "private" or "public".
 * @param {boolean} extractable Indicating if the raw information may be 
 * exported or not.
 * @param {AlgorithmIdentifier} algorithm Represents a cipher the key has to
 * be used with.
 * @param {string[]} usages Array of values indicating what the key can be 
 * used for.
 * @param {*} handle Contains the data which represents the logical
 * key
 * @returns {CryptoKey} The newly created CryptoKey object.
 */
function CryptoKey (type, extractable, algorithm, usages, handle) {
  Object.defineProperties( this, {
    type: {
      value: type,
      enumerable: true
    },
    extractable: {
      value: extractable,
      enumerable: true
    },
    algorithm: {
      value: algorithm,
      enumerable: true
    },
    usages: {
      value: usages,
      enumerable: true
    },
    _handle: {
      value: handle,
      enumerable: false
    }
  });
}

/**
 * Converts a polyfill CryptoKey to a native CryptoKey. If key is already
 * a native CryptoKey, it is returned.
 * 
 * @private
 * @param {CryptoKey} key The polyfill CryptoKey
 * @returns {Promise} A Promise that returns the native CryptoKey
 */
function polyToNativeCryptoKey(key) {
  
  if(isNativeCryptoKey(key)) {
    return Promise.resolve(key);
  }
  
  if(supportsOperation('exportKey', key.algorithm)) {
    // Key can be exported. Currently there is no algorithm for which keys
    // can be exported but not imported. So it is not necessary to check if
    // key can be imported
    
    var extractable = key.extractable;
    if(!extractable) {
      key = new CryptoKey(
              key.type, true, key.algorithm, key.usages, key._handle);
    }
    // JWK format is possible for all keys
    return exportKeyFallback('jwk', key).then(function(jwk) {
      return importKey('jwk', jwk, key.algorithm, extractable, key.usages);
    }).then(function(importedKey) {
      if(!isNativeCryptoKey(importedKey)) {
        throw new NotSupportedError("Conversion of key with algorithm '" 
            + key.algorithm.name + "' not supported");
      }
      return importedKey;
    });
  } else if(key.algorithm.name === 'PBKDF2') {
    // PBKDF2 key can only be imported in raw format, but polyfill
    // PBKDF2 CryptoKey contains key material in raw format
    return importKey(
            'raw', key._handle, key.algorithm, key.extractable, key.usages);
  } else {
    return Promise.reject(new NotSupportedError(
            'Conversion of key with algorithm "' 
            + key.algorithm.name + '" not supported'));
  }
}

/**
 * Converts a native CryptoKey to a polyfill CryptoKey. If key is already a
 * polyfill CryptoKey, it is returned.
 * 
 * @private
 * @param {CryptoKey} key The native CryptoKey
 * @returns {Promise} A Promise that returns the polyfill CryptoKey
 */
function nativeToPolyCryptoKey(key) {
  if(isPolyfillCryptoKey(key)) {
    return Promise.resolve(key);
  }
  return exporteKey('jwk', key).then(function(jwk) {
    return importKeyFallback(
            'jwk', jwk, key.algorithm, key.extractable, key.usages);
  });
}

/**
 * Generates cryptographically random values. The array given as the parameter 
 * is filled with random numbers (random in its cryptographic meaning).
 * 
 * @memberOf module:webcrypto
 * @param {Int8Array | Uint8Array | Uint16Array | Int32Array | Uint32Array} 
 * typedArray An integer-based TypedArray which is filled with random numbers. 
 * All elements in the array are going to be overridden.
 */
function getRandomValues(typedArray) {
  if(globalCrypto) {
    globalCrypto.getRandomValues(typedArray);
  } else if(asmCrypto) {
    asmCrypto.getRandomValues(typedArray);
  } else {
    throw new NotSupportedError("Function 'getRandomValues' not supported");
  }
}