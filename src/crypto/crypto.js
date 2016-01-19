var global = typeof importScripts !== 'function' ? window : self;
var isIE = !!global.msCrypto,
    isW3C = !!global.crypto,
    globalCrypto = global.crypto || global.msCrypto,
    subtle;

// The Key in IE has the property "keyUsages" instead of the property
// "usages" as specied in the latest W3C Web Cryptography API.
// But the property "keyUsages" is always null and read-only. Fix this
// by removing the property "keyUsages" and adding the writeable
// property "usages".
if(isIE && global.Key) {
  
  // Remove property "keyUsages"
  delete Key.prototype.keyUsage;
  
  // Add property "key"
  Object.defineProperty(Key.prototype, "usages", {
    enumerable: true,
  	writable: true,
    value: null
  });
};
    
if(globalCrypto) subtle = globalCrypto.subtle;

if(asmCrypto) {
  asmCrypto.random.skipSystemRNGWarning = true;
  asmCrypto.random.allowWeak = true;
};

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
      enumerable: true
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
  var notSupportedMessage = "Conversion of key with algorithm '" 
            + key.algorithm.name + "' not supported";
  
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
    
    var supportedFormats = getNativeSupportedFormats(
            key.algorithm, 'import', key.type);
    
    if(supportedFormats.length > 0) {
      return exportKeyFallback(supportedFormats[0], key).then(function(jwk) {
        return importKey(supportedFormats[0], jwk, key.algorithm, 
                extractable, key.usages);
      }).then(function(importedKey) {
        if(!isNativeCryptoKey(importedKey)) {
          throw new NotSupportedError(notSupportedMessage);
        }
        importedKey.usages = key.usages;
        return importedKey;
      });
    } else {
      return Promise.reject(new NotSupportedError(notSupportedMessage));
    };
  } else {
    return Promise.reject(new NotSupportedError(notSupportedMessage));
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
  var format;
  if(key.type === 'secret') {
    format = 'raw';
  } else {
    format = 'jwk';
  }
  return exportKey(format, key).then(function(keyData) {
    return importKeyFallback(
            format, keyData, key.algorithm, key.extractable, key.usages);
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
 * @returns {Int8Array | Uint8Array | Uint16Array | Int32Array | Uint32Array}
 * The filled array.
 */
function getRandomValues(typedArray) {
  if(globalCrypto) {
    globalCrypto.getRandomValues(typedArray);
  } else if(asmCrypto) {
    asmCrypto.getRandomValues(typedArray);
  } else {
    throw new NotSupportedError("Function 'getRandomValues' not supported");
  }
  return typedArray;
}