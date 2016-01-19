/*!
WebCrypto v0.0.1 
(c) 2015 Samuel Samtleben 
License: MIT 
*/
(function(root, factory) { 
	if (typeof define === "function" && define.amd) {
		define(["asmCrypto"], factory);
	} else if (typeof exports === "object") {
		module.exports = factory(require("asmCrypto")); 
	} else { 
		root.webCrypto = factory(root.asmCrypto);
	}
}(this, function (asmCrypto) {
	var exports = {};
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
/**
 * The webcrypto module provides access to all cryptographic methods.<br />
 * It is the equivalent to the Crypto interface.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto}
 * @module webcrypto
 */

exports.CryptoKey = CryptoKey;
exports.getRandomValues = getRandomValues;



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
/**
 * Creates a new AesGcmParams object.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#aes-gcm-params}
 * 
 * @private
 * @constructs AesGcmParams
 * @extends Algorithm
 * @returns {AesGcmParams} Newly created AesGcmParams object
 */
function AesGcmParams() {
  
  /**
   * The initialization vector to use. May be up to 2^64-1 bytes long.
   * 
   * @type {BufferSource}
   */
  this.iv;
  
  /**
   * The additional authentication data to include.
   * 
   * @type {BufferSource}
   */
  this.additionalData;
  
  /**
   * The desired length of the authentication tag. May be 0 - 128.
   * 
   * @type {number}
   */
  this.tagLength;
}
extend(Algorithm, AesGcmParams);

/**
 * Initializes this AesGcmParams with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the AesGcmParams.
 * @returns {AesGcmParams} The initialized AesGcmParams
 */
AesGcmParams.prototype.init = function(alg) {
  // Call parent init funtion
  AesGcmParams._super.init.call(this, alg);
  
  if(!isBufferSource(alg.iv)) {
    throw new TypeError('AesGcmParams: iv: Missing or not ' 
            + 'a BufferSource');
  }
  this.iv = alg.iv;
  
  if(alg.additionalData) {
    if(!isBufferSource(alg.additionalData)) {
      throw new TypeError('AesGcmParams: additionalData: Not a BufferSource');
    }
    this.additionalData = alg.additionalData;
  }
  
  if(alg.tagLength) {
    if(!isNumber(alg.tagLength)) {
      throw new TypeError('AesGcmParams: tagLength: Not a Number');
    }
    this.tagLength = alg.tagLength;
  }
  
  return this;
};

/**
 * Returns the encrypted data corresponding to the data, algorithm and key 
 * given as parameters.<br />
 * Can only be used with AES-GCM algorithm.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations}
 * 
 * @private
 * @param {Object} normAlgo The encryption function to use.
 * @param {CryptoKey} key The key to be used for the encryption.
 * @param {ArrayBuffer | ArrayBufferView} plaintext The data to be encrypted.
 * @returns {Promise} A Promise that returns the ciphertext generated by 
 * the encryption of the data as an ArrayBuffer.
 */
function encrypt_AES_GCM(normAlgo, key, plaintext) {
  if(plaintext.byteLength > (Math.pow(2, 39) - 256)) {
    throw new OperationError('"data" too large');
  }
  if(normAlgo.iv.byteLength > (Math.pow(2, 64) - 1)) {
    throw new OperationError('"iv" too large');
  }
  var tagLength;
  if(normAlgo.tagLength === undefined) {
    tagLength = 128;
  } else if(normAlgo.tagLength === 32 
          || normAlgo.tagLength === 64
          || normAlgo.tagLength === 96
          || normAlgo.tagLength === 104
          || normAlgo.tagLength === 112
          || normAlgo.tagLength === 120
          || normAlgo.tagLength === 128) {
    tagLength = normAlgo.tagLength;
  } else {
    throw new OperationError('Invalid "tagLength"');
  }
  
  var additionalData;
  if(normAlgo.additionalData === undefined) {
    additionalData = new ArrayBuffer(0);
  } else {
    additionalData = getBuffer(normAlgo.additionalData);
  }
  var ciphertext = asmCrypto.AES_GCM.encrypt(
          getBuffer(plaintext), 
          key._handle, 
          getBuffer(normAlgo.iv), 
          additionalData, 
          tagLength / 8);
  
  // TODO: Fix buffer length problem
  return new Uint8Array(ciphertext).buffer;
}

/**
 * Returns the cleartext corresponding to the ciphertext, algorithm and key 
 * given as parameters.<br />
 * Can only be used with AES-GCM algorithm.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations}
 * 
 * @private
 * @param {Object} normAlgo The encryption function to use.
 * @param {CryptoKey} key The key to be used for the decryption.
 * @param {ArrayBuffer | ArrayBufferView} ciphertext The data to be decrypted.
 * @returns {Promise} The cleartext corresponding to the ciphertext, algorithm
 * and key given as parameters.
 */
function decrypt_AES_GCM(normAlgo, key, ciphertext) {
  var tagLength;
  if(normAlgo.tagLength === undefined) {
    tagLength = 128;
  } else if(normAlgo.tagLength === 32 
          || normAlgo.tagLength === 64
          || normAlgo.tagLength === 96
          || normAlgo.tagLength === 104
          || normAlgo.tagLength === 112
          || normAlgo.tagLength === 120
          || normAlgo.tagLength === 128) {
    tagLength = normAlgo.tagLength;
  } else {
    throw new OperationError('Invalid "tagLength"');
  }
  if(ciphertext.byteLength * 8 < tagLength) {
    throw new OperationError('The provided data is too small');
  }
  if(normAlgo.iv.byteLength > Math.pow(2, 64) - 1) {
    throw new OperationError('"iv" is too large');
  }
  if(normAlgo.additionalData && 
          normAlgo.additionalData.byteLength > Math.pow(2, 64) - 1) {
    throw new OperationError('"additionalData" is too large');
  }
  var additionalData;
  if(normAlgo.additionalData === undefined) {
    additionalData = new ArrayBuffer(0);
  } else {
    additionalData = getBuffer(normAlgo.additionalData);
  }
  var plaintext = asmCrypto.AES_GCM.decrypt(
          getBuffer(ciphertext), 
          key._handle, 
          getBuffer(normAlgo.iv), 
          additionalData, 
          tagLength / 8);
  
  // TODO: Fix buffer length problem
  return new Uint8Array(plaintext).buffer;
}

/**
 * Creates a new AesKeyGenParams object.
 * 
 * @private
 * @constructs AesKeyGenParams
 * @extends Algorithm
 * @returns {AesKeyGenParams} ewly created AesKeyGenParams object.
 */
function AesKeyGenParams() {
  
  /**
   * The length, in bits, of the key.
   * 
   * @type {number}
   */
  this.length;
}
extend(Algorithm, AesKeyGenParams);

/**
 * Initializes this algorithm with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the algorithm.
 * @returns {RsaKeyGenParams} The initialized AesKeyGenParams
 */
AesKeyGenParams.prototype.init = function(alg) {
  // Call parent init funtion
  AesKeyGenParams._super.init.call(this, alg);
  
  if(!isNumber(alg.length)) {
   throw new TypeError('AesKeyGenParams: length: Missing or not ' 
            + 'a number'); 
  }
  this.length = alg.length;
  return this;
};



/**
 * Returns a newly generated AES CryptoKey.<br />
 * The CryptoKey is generated by using a fallback library.<br />
 * AES-GCM: @see {@link http://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations}
 * 
 * @private
 * @param {Object} normAlgo The key generation function to use.
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {String[]} keyUsages Indicating what can be done with the newly 
 * generated key.
 * @returns {Object} A newly generated AES CryptoKey
 */
function generateKey_AES(normAlgo, extractable, keyUsages) {
  
  if(arrayContainsOther(
          keyUsages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])) {
    throw new SyntaxError('Cannot create a key using the specified ' 
              + 'key usages.');
  }
  if(normAlgo.length !== 128 
          && normAlgo.length !== 192 
          && normAlgo.length !== 256) {
    throw new OperationError('AES key length must be 128, 192 or 256 bits');
  }
  var key;
  try {
    var randoms = new Uint8Array(normAlgo.length / 8);
    getRandomValues(randoms);
    var algorithm = {
      name: normAlgo.name,
      length: normAlgo.length
    };
    key = new CryptoKey(
            'secret',
            extractable,
            algorithm,
            keyUsages,
            randoms.buffer);
  } catch(err) {
    throw new OperationError(err);
  }
  return key;
}

/**
 * Returns the AES key in the requested format.<br />
 * AES-GCM: {@link http://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations}<br />
 * 
 * @private
 * @param {string} format The data format in which the key has to be exported.
 * @param {CryptoKey} key The AES CryptoKey to export.
 * @returns {*} The AES key in the requested format.
 */
function exportKey_AES(format, key) {
  var result;
  if(format === 'jwk') {
    var jwk = {};
    jwk.kty = "oct";
    jwk.k = bytesToBase64URL(new Uint8Array(key._handle));
    jwk.alg = algorithmToJWA(key.algorithm);
    jwk.key_ops = key.usages;
    jwk.ext = key.extractable;
    result = jwk;
    
  } else if (format === 'raw') {
    var data = key._handle;
    if(!isBufferSource(data)) {
      throw new OperationError('Invalid key format.');
    }
    result = getBuffer(data);
  } else {
    throw new NotSupportedError('Format "' + format + '" not supported');
  }
  return result;
}

/**
 * Returns the AES CryptoKey generated from the data given in
 * parameters.<br />
 * AES-GCM: {@link http://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations}
 * 
 * @private
 * @param {string} format the data format of the key to imported. Possible
 * values are "raw" (usually a secret key), "pkcs8" (private key), 
 * "skpi" (usually a public key) and "jwk".
 * @param {BufferSource | Object} keyData The key in the specified format.
 * @param {Object} normAlgo The normalized cryptographic algorithm for use 
 * with the output key object.
 * @param {boolean} extractable indicating if the key can be extracted from the 
 * CryptoKey object at a later stage.
 * @param {string[]} usages Indicating what can be done with the key.
 * @returns {CryptoKey} The generated AES CryptoKey.
 */
function importKey_AES(format, keyData, normAlgo, extractable, usages) {
  
  if(arrayContainsOther(
          usages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])) {
    throw new SyntaxError(
            'Cannot create a key using the specified key usages.');
  }
  
  var data;
  if(format === 'raw') {
    if(!isBufferSource(keyData)) {
      throw new DataError(
              'Key data must be a BufferSource for non-JWK formats');
    }
    data = getBuffer(keyData);
    if(data.byteLength !== 128 / 8
            && data.byteLength !== 192 / 8
            && data.byteLength !== 256 / 8) {
      throw new DataError('AES key data must be 128, 192 or 256 bits');
    }
    
  } else if(format === 'jwk') {
    var jwk = keyData;
    if(jwk.kty !== 'oct') {
      throw new DataError('The JWK "kty" member was not "oct"');
    }
    if(!jwk.k) {
      throw new DataError('JWK does not meet the requirements');
    }
    data = base64URLToBytes(jwk.k).buffer;
    if(jwk.alg) {
      var algo = jwaToAlgorithm(jwk.alg);
      if(algo.length !== data.byteLength * 8) {
        throw new DataError('The JWK "alg" member was inconsistent with ' 
                + 'that specified by the Web Crypto call');
      }
      
    }
    if(jwk.use && jwk.use !== 'enc') {
      throw new DataError('The JWK "use" member was not "enc"');
    }
    if(jwk.key_ops && arrayContainsOther(usages, jwk.key_ops)) {
      throw new DataError('The JWK "key_ops" member does not contain all ' 
              + 'of the specified usages values.');
    }
    if(jwk.ext !== undefined && jwk.ext === false && extractable) {
      throw new DataError('The JWK "ext" member was inconsistent with ' 
                + 'that specified by the Web Crypto call');
    }
  } else {
    throw new NotSupportedError('Format "' + format + '" not supported');
  }
  var algorithm = {
    name: normAlgo.name,
    length: data.byteLength * 8
  };
  return new CryptoKey('secret', false, algorithm, [], data);
}

/**
 * Returns the length, in bits, of the key.
 * 
 * @private
 * @param {AesKeyGenParams} normAlgo The normalized algirithm
 * @returns {number} The length, in bits, of the key.
 */
function getKeyLength_AES(normAlgo) {
  if(normAlgo.length !== 128 
          && normAlgo.length === 192 
          && normAlgo.length === 256) {
    throw new OperationError('Invalid key length. Must be 128, 192 or 256');
  }
  return normAlgo.length;
}
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
/**
 * Creates a new Pbkdf2Params object.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-Pbkdf2Params}
 * 
 * @private
 * @constructs Pbkdf2Params
 * @extends Algorithm
 * @returns {Pbkdf2Params} Newly created Pbkdf2Params object
 */
function Pbkdf2Params() {
  
  /**
   * The salt which should be used to generate the key.
   * 
   * @type {BufferSource}
   */
  this.salt;
  
  /**
   * The number of iterations.
   * 
   * @type {number}
   */
  this.iterations;
  
  /**
   * The hash algorithm to use.
   * 
   * @type {HashAlgorithmIdentifier}
   */
  this.hash;
}
extend(Algorithm, Pbkdf2Params);

/**
 * Initializes this algorithm with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the algorithm.
 * @returns {Pbkdf2Params} The initialized Pbkdf2Params
 */
Pbkdf2Params.prototype.init = function(alg) {
  // Call parent init function
  Pbkdf2Params._super.init.call(this, alg);
  
  if(!isBufferSource(alg.salt)) {
    throw new TypeError('Pbkdf2Params: salt: Missing or not a BufferSource');
  }
  this.salt = alg.salt;
  
  if(!isNumber(alg.iterations)) {
    throw new TypeError('Pbkdf2Params: iterations: Missing or not a number');
  }
  this.iterations = alg.iterations;
  
  if(!isHashAlgorithmIdentifier(alg.hash)) {
    throw new TypeError(
            'Pbkdf2Params: hash: Missing or not a HashAlgorithmIdentifier');
  }
  this.hash = alg.hash;
  
  return this;
};


/**
 * Returns the PBKDF2 base CryptoKey generated from the data given in
 * parameters.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#pbkdf2}
 * 
 * @private
 * @param {string} format the data format of the key to imported. The only 
 * possible value is "raw".
 * @param {BufferSource} keyData The key in the specified format.
 * @param {Object} normAlgo The normalized cryptographic algorithm for use 
 * with the output key object.
 * @param {boolean} extractable indicating if the key can be extracted from the 
 * CryptoKey object at a later stage.
 * @param {string[]} usages Indicating what can be done with the key.
 * @returns {CryptoKey} The generated PBKDF2 CryptoKey.
 */
function importKey_PBKDF2(format, keyData, normAlgo, extractable, usages) {
  if(format !== 'raw') {
    throw new NotSupportedError('Format "' + format + '" not supported');
  }
  if(arrayContainsOther(usages, ['deriveKey', 'deriveBits'])) {
    throw new SyntaxError(
            'Cannot create a key using the specified key usages.');
  }
  if(!isBufferSource(keyData)) {
    throw new DataError('"keyData" does not meet requirements');
  }
  var _handle = getBuffer(keyData);
  
  var algorithm = new KeyAlgorithm('PBKDF2');
  return new CryptoKey('secret', false, algorithm, [], _handle);
};

/**
 * Returns the PBKDF2 key in the requested format.<br />
 * <b>Note:</b> This opertaion is not specified by W3C.
 * 
 * @private
 * @param {string} format The data format in which the key has to be exported.
 * @param {CryptoKey} key The PBKDF2 CryptoKey to export.
 * @returns {*} The PBKDF2 key in the requested format.
 */
function exportKey_PBKDF2(format, key) {
  var result;
  if (format === 'raw') {
    var data = key._handle;
    if(!isBufferSource(data)) {
      throw new OperationError('Invalid key format.');
    }
    result = getBuffer(data);
  } else {
    throw new NotSupportedError('Format "' + format + '" not supported');
  }
  return result;
};

/**
 * Generates a new BufferSource of bits derived from a master key.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#pbkdf2-operations}
 * 
 * @private
 * @param {Pbkdf2Params} normalizedAlgorithm The normalized algorithm.
 * @param {CryptoKey} baseKey The base key to be used by the key derivation 
 * algorithm.
 * @param {number} length The length, in bits, of the generated BufferSource.
 * @returns {BufferSource} The generated BufferSource of bits.
 */
function deriveBits_PBKDF2(normalizedAlgorithm, baseKey, length) {
  if(length % 8 !== 0) {
    throw new OperationError('"length" must be a multiple of 8');
  }
  
  ensureOperation('digest', normalizedAlgorithm.hash);
  
  var result;
  switch(normalizedAlgorithm.hash.name) {
    case 'SHA-1':
      result = asmCrypto.PBKDF2_HMAC_SHA1.bytes(
              getBuffer(baseKey._handle), 
              getBuffer(normalizedAlgorithm.salt), 
              normalizedAlgorithm.iterations, 
              length / 8);
      break;
    case 'SHA-256':
      result = asmCrypto.PBKDF2_HMAC_SHA256.bytes(
              getBuffer(baseKey._handle), 
              getBuffer(normalizedAlgorithm.salt), 
              normalizedAlgorithm.iterations, 
              length / 8);
      break;
    case 'SHA-512':
      result = asmCrypto.PBKDF2_HMAC_SHA512.bytes(
              getBuffer(baseKey._handle), 
              getBuffer(normalizedAlgorithm.salt), 
              normalizedAlgorithm.iterations, 
              length / 8);
      break;
    default:
      throw new NotSupportedError(
              'PBKDF2 with hash "' 
              + normalizedAlgorithm.hash.name 
              + '" not supported');
  }
  
  // TODO: Check result buffer length problem
  return result;
}
/**
 * Creates a new RsaOaepParams object.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-RsaOaepParams}
 * 
 * @private
 * @constructs RsaOaepParams
 * @extends Algorithm
 * @returns {RsaOaepParams} Newly created RsaOaepParams object
 */
function RsaOaepParams() {
  
  /**
   * The optional label/application data to associate with the message.
   * 
   * @type {BufferSource}
   */
  this.label;
}
extend(Algorithm, RsaOaepParams);

/**
 * Initializes this RsaOaepParams with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the RsaOaepParams.
 * @returns {RsaOaepParams} The initialized RsaOaepParams
 */
RsaOaepParams.prototype.init = function(alg) {
  // Call parent init function
  RsaOaepParams._super.init.call(this, alg);
  
  if(alg.label) {
    if(!isBufferSource(alg.label)) {
      throw new TypeError('RsaOapParams: label: Not a BufferSource');
    }
    this.label = alg.label;
  }
  return this;
};


/**
 * Returns the encrypted data corresponding to the data, algorithm and key 
 * given as parameters.<br />
 * Can only be used with RSA-OAEP algorithm.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations}
 * 
 * @private
 * @param {Object} normAlgo The encryption function to use.
 * @param {CryptoKey} key The key to be used for the encryption.
 * @param {ArrayBuffer | ArrayBufferView} plaintext The data to be encrypted.
 * @returns {Promise} A Promise that returns the ciphertext generated by 
 * the encryption of the data as an ArrayBuffer.
 */
function encrypt_RSA_OAEP(normAlgo, key, plaintext) {
  
  if(key.type !== 'public') {
    throw new InvalidAccessError(
            'key.usages does not permit this operation');
  }

  var label;
  if(normAlgo.label === undefined) {
    label = new ArrayBuffer(0);
  } else {
    label = getBuffer(normAlgo.label);
  }
      
  var encFn;
  switch(key.algorithm.hash.name) {
    case "SHA-256":
      encFn = asmCrypto.RSA_OAEP_SHA256.encrypt;
      break;
    default:
      throw new NotSupportedError('Not supported yet: hash: ' 
              + key.algorithm.hash.name);
  }
  try {
    var ciphertext = encFn(getBuffer(plaintext), key._handle, label);
  } catch(err) {
    throw new OperationError(err);
  }
  
  // TODO: Fix buffer length problem
  // Plaintext is alread Uint8Array but its internal buffer has
  // wrong byteLength. Solve this by create a new ArrayBuffer.
  return new Uint8Array(ciphertext).buffer;
}

/**
 * Returns the cleartext corresponding to the ciphertext, algorithm and key 
 * given as parameters.<br />
 * Can only be used with RSA-OAEP algorithm.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations}
 * 
 * @private
 * @param {Object} normAlgo The encryption function to use.
 * @param {CryptoKey} key The key to be used for the decryption.
 * @param {ArrayBuffer | ArrayBufferView} ciphertext The data to be decrypted.
 * @returns {Promise} The cleartext corresponding to the ciphertext, algorithm
 * and key given as parameters.
 */
function decrypt_RSA_OAEP(normAlgo, key, ciphertext) {
  
  if(key.type !== 'private') {
    throw new InvalidAccessError(
            'key.usages does not permit this operation');
  }
  var label;
  if(normAlgo.label === undefined) {
    label = new ArrayBuffer(0);
  } else {
    label = getBuffer(normAlgo.label);
  }
  
  var decFn;
  switch(key.algorithm.hash.name) {
    case "SHA-256":
      decFn = asmCrypto.RSA_OAEP_SHA256.decrypt;
      break;
    default:
      throw new NotSupportedError('Not supported yet: hash: ' 
              + key.algorithm.hash.name);
  }
  try {
    var plaintext = decFn(getBuffer(ciphertext), key._handle, label);
  } catch(err) {
    throw new OperationError(err);
  }
  
  // TODO: Fix buffer length problem
  // Plaintext is alread Uint8Array but its internal buffer has
  // wrong byteLength. Solve this by create a new ArrayBuffer.
  return new Uint8Array(plaintext).buffer;
}
/**
 * Creates a new RsaKeyGenParms object.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-RsaKeyGenParams}
 * 
 * @private
 * @constructs RsaKeyGenParams
 * @extends Algorithm
 * @returns {RsaKeyGenParams} Newly created RsaKeyGenParms object.
 */
function RsaKeyGenParams() {
  
  /**
   * The length, in bits, of the RSA modulus.
   * 
   * @type {number}
   */
  this.modulusLength;
  
  /**
   * The RSA public exponent.
   * 
   * @type {Uint8Array}
   */
  this.publicExponent;
}
extend(Algorithm, RsaKeyGenParams);

/**
 * Initializes this algorithm with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the algorithm.
 * @returns {RsaKeyGenParams} The initialized RsaKeyGenParams
 */
RsaKeyGenParams.prototype.init = function(alg) {
  // Call parent init function
  RsaKeyGenParams._super.init.call(this, alg);
  
  if(!isNumber(alg.modulusLength)) {
    throw new TypeError(
            'RsaKeyGenParams: modulusLength: Missing or not a number');
  }
  this.modulusLength = alg.modulusLength;
  
  if(!alg.publicExponent || !isBigInteger(alg.publicExponent)) {
    throw new TypeError(
            'RsaKeyGenParams: publicExponent: Missing or not a BigInteger');
  }
  this.publicExponent = alg.publicExponent;
  return this;
};

/**
 * Creates a new RsaHashedKeyGenParams object.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-RsaHashedKeyGenParams}
 * 
 * @private
 * @constructs RsaHashedKeyGenParams
 * @extends RsaKeyGenParams
 * @returns {RsaHashedKeyGenParams} Newly created RsaHashedKeyGenParams object.
 */
function RsaHashedKeyGenParams() {
  
  /**
   * The hash algorithm to use.
   * 
   * @type {HashAlgorithmIdentifier}
   */
  this.hash;
}
extend(RsaKeyGenParams, RsaHashedKeyGenParams);

/**
 * Initializes this algorithm with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the algorithm.
 * @returns {RsaKeyGenParams} The initialized RsaHashedKeyGenParams
 */
RsaHashedKeyGenParams.prototype.init = function(alg) {
  // Call parent init function
  RsaHashedKeyGenParams._super.init.call(this, alg);
  
  if(!isHashAlgorithmIdentifier(alg.hash)) {
    throw new TypeError(
      'RsaHashedKeyGenParms: hash: Missing or not a HashAlgorithmIdentifier');
  }
  this.hash = alg.hash;
  return this;
};

/**
 * Creates a new RsaHashedImportParams object.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-RsaHashedImportParams}
 * 
 * @private
 * @constructs RsaHashedImportParams
 * @extends Algorithm
 * @returns {RsaHashedImportParams} Newly created RsaHashedImportParams object.
 */
function RsaHashedImportParams() {
  
  /**
   * The hash algorithm to use.
   * 
   * @type {HashAlgorithmIdentifier}
   */
  this.hash;
}
extend(Algorithm, RsaHashedImportParams);

/**
 * Initializes this algorithm with the values given as paramter.
 * 
 * @private
 * @param {object} alg The values which should be used to intitialize
 * the algorithm.
 * @returns {RsaKeyGenParams} The initialized RsaHashedImportParams
 */
RsaHashedImportParams.prototype.init = function(alg) {
  // Call parent init function
  RsaHashedImportParams._super.init.call(this, alg);
  
  if(!isHashAlgorithmIdentifier(alg.hash)) {
    throw new TypeError(
      'RsaHashedImportParams: hash: Missing or not a HashAlgorithmIdentifier');
  }
  this.hash = alg.hash;
  return this;
};

/**
 * Returns a newly generated RSA CryptoKeyPair, containing 
 * two newly generated keys.<br />
 * The CryptoKeyPair is generated by using a fallback library.<br />
 * RSA-OAEP: {@link http://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations}
 * 
 * @private
 * @param {Object} normAlgo The key generation function to use.
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {String[]} keyUsages Indicating what can be done with the newly 
 * generated key.
 * @returns {Object} A newly generated RSA CryptoKeyPair, containing 
 * two newly generated keys.
 */
function generateKey_RSA(normAlgo, extractable, keyUsages) {
    
    if(arrayContainsOther(
            keyUsages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])) {
      throw new SyntaxError(
              'Cannot create a key using the specified key usages.');
    }
    
    try {
      // RSA.generateKey -> [ n, e, d, p, q, dp, dq, qi ]
      var asmKey = asmCrypto.RSA.generateKey(
              normAlgo.modulusLength, 
              normAlgo.publicExponent);
    } catch(err) {
      throw new OperationError(err);
    }
    
    var algorithm = {};
    algorithm.name = normAlgo.name;
    algorithm.modulusLength = normAlgo.modulusLength;
    algorithm.publicExponent = normAlgo.publicExponent;
    algorithm.hash = normAlgo.hash;
    
    var publicKey = new CryptoKey(
            'public', 
            true, 
            algorithm, 
            arrayIntersect(keyUsages, ['encrypt', 'wrapKey']),
            [asmKey[0], asmKey[1]]);
    
    var privateKey = new CryptoKey(
            'private',
            extractable,
            algorithm,
            arrayIntersect(keyUsages, ['decrypt', 'unwrapKey']),
            asmKey);


    var result = {
      publicKey: publicKey,
      privateKey: privateKey
    };
    return result;
}

/**
 * Returns the RSA key in the requested format.<br />
 * RSA-OAEP: {@link http://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations}<br />
 * RSA-PSS: {@link http://www.w3.org/TR/WebCryptoAPI/#rsa-pss-operations}<br />
 * RSASSA-PKCS1-v1_5: {@link http://www.w3.org/TR/WebCryptoAPI/#rsassa-pkcs1-operations}
 * 
 * @private
 * @param {string} format The data format in which the key has to be exported.
 * @param {CryptoKey} key The RSA CryptoKey to export.
 * @returns {*} The RSA key in the requested format.
 */
function exportKey_RSA(format, key) {
  var result;
  if(format === 'jwk') {
    var jwk = {};
    jwk.kty = "RSA";
    jwk.alg = algorithmToJWA(key.algorithm);
    jwk.n = bytesToBase64URL(key._handle[0]);
    jwk.e = bytesToBase64URL(key._handle[1]);
    if(key.type === "private") {
      jwk.d = bytesToBase64URL(key._handle[2]);
      jwk.p = bytesToBase64URL(key._handle[3]);
      jwk.q = bytesToBase64URL(key._handle[4]);
      jwk.dp = bytesToBase64URL(key._handle[5]);
      jwk.dq = bytesToBase64URL(key._handle[6]);
      jwk.qi = bytesToBase64URL(key._handle[7]);
    }
    jwk.key_ops = key.usages;
    jwk.ext = key.extractable;
    result = jwk;
  } else {
    throw new NotSupportedError("Export format '" + format 
            + "' not supported by algorithm '" + key.algorithm.name + "'");
  }
  return result;
};

/**
 * Returns the RSA CryptoKey generated from the data given in
 * parameters.<br />
 * RSA-OAEP: {@link http://www.w3.org/TR/WebCryptoAPI/#rsa-oaep-operations}
 * 
 * @private
 * @param {string} format the data format of the key to imported. Possible
 * values are "raw" (usually a secret key), "pkcs8" (private key), 
 * "skpi" (usually a public key) and "jwk".
 * @param {BufferSource | Object} keyData The key in the specified format.
 * @param {Object} normAlgo The normalized cryptographic algorithm for use 
 * with the output key object.
 * @param {boolean} extractable indicating if the key can be extracted from the 
 * CryptoKey object at a later stage.
 * @param {string[]} usages Indicating what can be done with the key.
 * @returns {CryptoKey} The generated RSA CryptoKey.
 */
function importKey_RSA(format, keyData, normAlgo, extractable, usages) {
    
  var _handle,
      keyType;
  if(format === "jwk") {

    var jwk = keyData;
    if((jwk.d && arrayContainsOther(usages, ['decrypt', 'unwrapKey'])) 
        || (!jwk.d && arrayContainsOther(usages, ['encrypt', 'wrapKey']))) {
      throw new SyntaxError('Cannot create a key using the specified ' 
              + 'key usages.');
    }
    if(!keyData.kty) {
      throw new SyntaxError('The required JWK member "kty" was missing');
    }
    if(keyData.kty !== "RSA") {
      throw new DataError('The JWK "kty" member was not "RSA"');
    }
    if(jwk.use && jwk.use !== 'enc') {
      throw new DataError('The JWK "use" member was not "enc"');
    }
    if(jwk.key_ops && arrayContainsOther(usages, jwk.key_ops)) {
      throw new DataError('The JWK "key_ops" member does not contain all ' 
              + 'of the specified usages values.');
    }

    if(jwk.alg) {
      var jwkAlg = jwaToAlgorithm(jwk.alg);
      if(jwkAlg.name !== normAlgo.name || !jwkAlg.hash) {
        throw new DataError('The JWK "alg" member was inconsistent with ' 
                + 'that specified by the Web Crypto call');
      } else {
        var hash = jwkAlg.hash.name;
        var normHash = normalizeAlgorithm("digest", hash);
        if(normHash.name !== normAlgo.hash.name) {
          throw new DataError('The JWK "alg" member was inconsistent with ' 
                + 'that specified by the Web Crypto call');
        }
      }
    }

    if(jwk.d) {
      if(jwk.n && jwk.e && jwk.d && jwk.p && jwk.q && jwk.dp && jwk.dq 
              && jwk.qi) {
        _handle = [
          base64URLToBytes(jwk.n),
          base64URLToBytes(jwk.e),
          base64URLToBytes(jwk.d),
          base64URLToBytes(jwk.p),
          base64URLToBytes(jwk.q),
          base64URLToBytes(jwk.dp),
          base64URLToBytes(jwk.dq),
          base64URLToBytes(jwk.qi)
        ];
        keyType = "private";
      } else {
        throw new DataError('JWK does not meet the requirements');
      }
    } else {
      if(jwk.n && jwk.e) {
        _handle = [
          base64URLToBytes(jwk.n),
          base64URLToBytes(jwk.e)
        ];
        keyType = "public";
      } else {
        throw new DataError('JWK does not meet the requirements');
      }
    }
  } else {
    throw new NotSupportedError('Format "' + format 
            + '" not yet supported');
  }

  var algorithm = {};
  algorithm.name = normAlgo.name;
  algorithm.modulusLength = _handle[0].length * 8;
  algorithm.publicExponent = new Uint8Array(_handle[1]);
  algorithm.hash = normAlgo.hash;

  return new CryptoKey(keyType, false, algorithm, [], _handle);
}
/**
 * Generates a digest from the hash function and data given as parameters.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#sha}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The hash function to use
 * @param {BufferSource} data The data to be hashed
 * @returns {ArrayBuffer} The hash as ArrayBuffer
 */
function digest_SHA(normalizedAlgorithm, data) {
  var result;
  try {
    var buffer = getBuffer(data);
    var digest;
    switch (normalizedAlgorithm.name) {
      case 'SHA-1':
        digest = asmCrypto.SHA1.bytes(buffer);
        break;
      case 'SHA-256':
        digest = asmCrypto.SHA256.bytes(buffer);
        break;
      case 'SHA-512':
        digest = asmCrypto.SHA512.bytes(buffer);
        break;
    }
    result = digest.buffer;
  } catch(err) {
    throw new OperationError(err.message);
  }
  
  // TODO: Check buffer length problem
  return result;
}
/**
 * Contains the information about supported import and export formats
 * for each algorithm. If algorithm, method or format is not included, the
 * operation is not supported.
 * 
 * @private
 * @type {object}
 */
var nativeImportExportSupport = {
  'RSASSA-PKCS1-v1_5': {
    'import': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    },
    'export': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    }
  },
  'RSA-PSS': {
    'import': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    },
    'export': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    }
  },
  'RSA-OAEP': {
    'import': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    },
    'export': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    }
  },
  'ECDSA': {
    'import': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    },
    'export': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'jwk': true,
        'skpi': true
      }
    }
  },
  'ECDH': {
    'import': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'raw': true,
        'jwk': true,
        'skpi': true
      }
    },
    'export': {
      'private': {
        'jwk': true,
        'pkcs8': true
      },
      'public': {
        'raw': true,
        'jwk': true,
        'skpi': true
      }
    }
  },
  'AES-CTR': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'AES-CBC': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'AES-CMAC': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'AES-GCM': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'AES-CFB': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'AES-KW': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'HMAC': {
    'import': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    },
    'export': {
      'secret': {
        'raw': true,
        'jwk': true
      }
    }
  },
  'DH': {
    'import': {
      'private': {
        'pkcs8': true
      },
      'public': {
        'raw': true,
        'spki': true
      }
    },
    'export': {
      'private': {
        'raw': true,
        'pkcs8': true
      },
      'public': {
        'raw': true,
        'spki': true
      }
    }
  },
  'CONCAT': {
    'import': {
      'secret': {
        'raw': true
      }
    }
  },
  'HKDF-CTR': {
    'import': {
      'secret': {
        'raw': true
      }
    }
  },
  'PBKDF2': {
    'import': {
      'secret': {
        'raw': true
      }
    }
  }
};

/**
 * Contains the implemented fallback operations.
 * 
 * @private
 * @type {object}
 */
var algorithmFallbackOperations = {
  'encrypt': {
    'RSA-OAEP': encrypt_RSA_OAEP,
    'AES-GCM': encrypt_AES_GCM
  },
  'decrypt': {
    'RSA-OAEP': decrypt_RSA_OAEP,
    'AES-GCM': decrypt_AES_GCM
  },
  'sign': {},
  'verify': {},
  'digest': {
    'SHA-1': digest_SHA,
    'SHA-256': digest_SHA,
    'SHA-512': digest_SHA
  },
  'generateKey': {
    'RSASSA-PKCS1-v1_5': generateKey_RSA,
    'RSA-PSS': generateKey_RSA,
    'RSA-OAEP': generateKey_RSA,
    'AES-CTR': generateKey_AES,
    'AES-CBC': generateKey_AES,
    'AES-CMAC': generateKey_AES,
    'AES-GCM': generateKey_AES,
    'AES-CFB': generateKey_AES,
    'AES-KW': generateKey_AES
  },
  'getKeyLength': {
    'AES-CTR': getKeyLength_AES,
    'AES-CBC': getKeyLength_AES,
    'AES-CMAC': getKeyLength_AES,
    'AES-GCM': getKeyLength_AES,
    'AES-CFB': getKeyLength_AES,
    'AES-KW': getKeyLength_AES
  },
  'deriveBits': {
    'PBKDF2': deriveBits_PBKDF2
  },
  'importKey': {
    'RSASSA-PKCS1-v1_5': importKey_RSA,
    'RSA-PSS': importKey_RSA,
    'RSA-OAEP': importKey_RSA,
    'AES-CTR': importKey_AES,
    'AES-CBC': importKey_AES,
    'AES-CMAC': importKey_AES,
    'AES-GCM': importKey_AES,
    'AES-CFB': importKey_AES,
    'AES-KW': importKey_AES,
    'PBKDF2': importKey_PBKDF2
  },
  'exportKey': {
    'RSASSA-PKCS1-v1_5': exportKey_RSA,
    'RSA-PSS': exportKey_RSA,
    'RSA-OAEP': exportKey_RSA,
    'AES-CTR': exportKey_AES,
    'AES-CBC': exportKey_AES,
    'AES-CMAC': exportKey_AES,
    'AES-GCM': exportKey_AES,
    'AES-CFB': exportKey_AES,
    'AES-KW': exportKey_AES,
    'PBKDF2': exportKey_PBKDF2
  },
  'wrapKey': {},
  'unwrapKey': {}
};

/**
 * Specifies combinations of methods and error names for which the
 * fallback function should be used.
 * 
 * @private
 * @type {object}
 */
var methodFallbackErrors = {
  'default': ['NotSupportedError'],
  'encrypt': [],
  'decrypt': [],
  'sign': [],
  'verify': [],
  'digest': [],
  'generateKey': ['OperationError'],
  'deriveKey': ['OperationError'],
  'deriveBits': ['OperationError'],
  'importKey': ['Error'],
  'exportKey': [],
  'wrapKey': [],
  'unwrapKey': ['Error']
};

/**
 * Creates a new Algorithm object.<br />
 * The Algorithm object is used to specify an algorithm and any additional 
 * parameters required to fully specify the desired operation.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-Algorithm}
 * 
 * @constructs Algorithm
 * @private
 * @returns {Algorithm} Newly created Algorithm object
 */
function Algorithm() {
  
  /**
   * The name of the registered algorithm.
   * 
   * @type {string}
   */
  this.name;
}

/**
 * Initializes this algorithm with the values given as paramter.
 * 
 * @private
 * @param {AlgorithmIdentifier} alg The values which should be used to 
 * intitialize the algorithm.
 * @returns {Algorithm} The initialized algorithm.
 */
Algorithm.prototype.init = function(alg) {
  if(!alg.name || !isString(alg.name)) {
    throw new TypeError('Algorithm: name: Missing or not a string');
  }
  this.name = alg.name;
  return this;
};

/**
 * Creates a new KeyAlgorithm object.<br />
 * The KeyAlgorithm dictionary represents information about the contents of 
 * a given CryptoKey object.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-KeyAlgorithm}
 * 
 * @constructs KeyAlgorithm
 * @private
 * @param {string} name The name of the algorithm which can be used with 
 * the key.
 * @returns {KeyAlgorithm} The newly created KeyAlgorithm object
 */
function KeyAlgorithm(name) {
  
  /**
   * The name of the algorithm which can be used with the key.
   * 
   * @type {string}
   */
  this.name = name;
};

/**
 * Returns the supported formats to import or export a key with the 
 * speciefied properies.
 * 
 * @private
 * @param {AlgorithmIdentifier} alg The name of the algorithm.
 * @param {string} op The type of operation (import or export).
 * @param {string} keyType The type of the key (secret, privat or public).
 * @returns {Array<string>} Supported formats.
 */
function getNativeSupportedFormats(alg, op, keyType) {
  var algName = alg.name || alg;
  var supportedFormats = [];
  if(nativeImportExportSupport[algName]
      && nativeImportExportSupport[algName][op]
      && nativeImportExportSupport[algName][op][keyType]) {

    var formats = nativeImportExportSupport[algName][op][keyType];
    var keys = Object.keys(formats);
    for(var i = 0; i < keys.length; i++) {
      if(formats[keys[i]]) {
        supportedFormats.push(keys[i]);
      };
    };
    
  };
  return supportedFormats;
};

/**
 * Checks if the import method is supported for the specified parameters.
 * 
 * @private
 * @param {AlgorithmIdentifier} alg The name of the algorithm.
 * @param {string} op The type of operation (import or export).
 * @param {string} keyType The type of the key (secret, privat or public).
 * @param {string} format The format of the key to import.
 * @returns {boolean} true if supported, false otherwise
 */
function isNativeSupported(alg, op, keyType, format) {
  var algName = alg.name = alg;
  var supported = false;
  if(nativeImportExportSupport[algName]
      && nativeImportExportSupport[algName][op]
      && nativeImportExportSupport[algName][op][keyType]
      && (nativeImportExportSupport[algName][op][keyType])
              .hasOwnProperty(format)) {
    supported = nativeImportExportSupport[algName][op][keyType][format];
  };
  return supported;
};

/**
 * Sets native import support to false for the specified parameters.
 * 
 * @private
 * @param {AlgorithmIdentifier} alg The name of the algorithm.
 * @param {string} op The type of operation (import or export).
 * @param {string} keyType The type of the key (secret, privat or public).
 * @param {string} format The format of the key to import.
 */
function setNativeUnsupported(alg, op, keyType, format) {
  var algName = alg.name || alg;
  if(nativeImportExportSupport[algName]
      && nativeImportExportSupport[algName][op]
      && nativeImportExportSupport[algName][op][keyType]
      && (nativeImportExportSupport[algName][op][keyType])
              .hasOwnProperty(format)) {
    nativeImportExportSupport[algName][op][keyType][format] = false;
  };
};

/**
 * Returns the key type (secret, private or public) for the specified
 * key parameters.
 * 
 * @private
 * @param {AlgorithmIdentifier} alg The algorithm identifier.
 * @param {string} format The key format (raw, jwk, pkcs8 or spki).
 * @param {object|ArrayBuffer} keyData The key data.
 * @returns {string} The key type for the specified key parameters.
 */
function getKeyType(alg, format, keyData) {
  var algName = alg.name || alg;
  var type = null;
  switch(algName) {
    case 'AES-CTR':
    case 'AES-CBC':
    case 'AES-CMAC':
    case 'AES-GCM':
    case 'AES-CFB':
    case 'AES-KW':
    case 'HMAC':
    case 'CONCAT':
    case 'HKDF-CTR':
    case 'PBKDF2':
      type = 'secret';
      break;
    case 'RSASSA-PKCS1-v1_5':
    case 'RSA-PSS':
    case 'RSA-OAEP':
    case 'ECDSA':
    case 'ECDH':
      if(format === 'pkcs8') {
        type = 'private';
        
      } else if (format === 'spki') {
        type = 'public';
        
      } else if (format === 'jwk' && algName !== 'DH') {
        if(keyData.d) {
          type = 'private';
        } else {
          type = 'public';
        }
        
      } else if (format === 'raw' && (algName === 'ECDH' || algName === 'DH')) {
        type = 'public';
        
      } else {
        throw new NotSupportedError("Format '" + format 
                + "' not supported for algorithm: " + algName);
      };
      break;
    default:
      throw new NotSupportedError(
              'The algorithm is not supported: ' + algName);
  };
  return type;
};

/**
 * Returns the JWA algorithm name of the algorithm given as parameter.<br />
 * @see {@link https://tools.ietf.org/html/rfc7518}<br />
 * <br />
 * Added the following algorithm names which are not specified by RFC 
 * 7518:<br />
 * <ul>
  * <li>RSA-OAEP-384</li>
  * <li>RSA-OAEP-512</li>
 * </ul>
 * 
 * @private
 * @author Samuel Samtleben
 * @param {AlgorithmIdentifier|Algorithm} algo The algorithm object
 * @returns {string} The JWA algorithm name
 */
function algorithmToJWA(algo) {;
  return {
    'HMAC': {
      'SHA-1': 'HS1',
      'SHA-256': 'HS256',
      'SHA-384': 'HS384',
      'SHA-512': 'HS512'
    },
    'RSASSA-PKCS1-v1_5': {
      'SHA-1': 'RS1',
      'SHA-256': 'RS256',
      'SHA-384': 'RS384',
      'SHA-512': 'RS512'
    },
    'RSAES-PKCS1-v1_5': {
      '': 'RSA1_5'
    },
    'RSA-OAEP': {
      'SHA-1': 'RSA-OAEP',
      'SHA-256': 'RSA-OAEP-256',
      'SHA-384': 'RSA-OAEP-384',
      'SHA-512': 'RSA-OAEP-512'
    },
    'AES-KW': {
      '128': 'A128KW',
      '192': 'A192KW',
      '256': 'A256KW'
    },
    'AES-GCM': {
      '128': 'A128GCM',
      '192': 'A192GCM',
      '256': 'A256GCM'
    },
    'AES-CBC': {
      '128': 'A128CBC',
      '192': 'A192CBC',
      '256': 'A256CBC'
    }
  }[algo.name][(algo.hash || {}).name || algo.length || ''];
}

/**
 * Returns the algorithm corresponding to the "jwa" given as parameter.<br />
 * @see {@link https://tools.ietf.org/html/rfc7518} and 
 * {@link http://www.w3.org/TR/WebCryptoAPI/#jwk-mapping} <br />
 * <br />
 * Attention: The returned algorithm is not normalized or checked for validity.
 * 
 * @private
 * @param {string} jwa The JWA string.
 * @returns {Object} The algorithm object corresponding to the "jwa" given 
 * as parameter.
 */
function jwaToAlgorithm(jwa) {
  var num = jwa.match(/\d+/g) || '1';
  var alg = jwa.match(/[A-Z]+/g).join('-');
  
  var algorithmName = {
    "RS": "RSASSA-PKCS1-v1_5",
    "PS": "RSA-PSS",
    "RSA-OAEP": "RSA-OAEP",
    "ES": "ECDSA",
    "A-CTR": "AES-CTR",
    "A-CBC": "AES-CBC",
    "A-KW": "AES-KW",
    "A-GCM": "AES-GCM",
    "A-GCMKW": "AES-GCM",
    "HS": "HMAC"
  }[alg] || '';
  
  var algorithm = {
    name: algorithmName
  };
  switch(algorithmName) {
    case "RSASSA-PKCS1-v1_5":
    case "RSA-PSS":
    case "RSA-OAEP":
    case "HMAC":
      algorithm.hash = {
        name: "SHA-" + num
      };
      break;
    case "ECDSA":
      algorithm.hash = {
        name: "SHA-" + num
      };
      algorithm.namedCurve = "P-" + (num === "512" ? "521" : num);
      break;
    case "AES-CTR":
    case "AES-CBC":
    case "AES-KW":
    case "AES-GCM":
      algorithm.length = parseInt(num);
      break;
  }
  return algorithm;
}

/**
 * Retuns an array of allowed key usages to the corresponding JWK "use"
 * value.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#jwk-mapping-usage}
 * 
 * @private
 * @param {string} use The value of the JWK "user" member.
 * @returns {string[]} The allowed key usages
 */
function getJWKUsageMapping(use) {
  if(use === "enc") {
    return ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
  } else if(use === "sig") {
    return ["sign", "verify"];
  } else {
    throw new SyntaxError("The JWK 'use' member could not be parsed");
  }
}

/**
 * This function decides based on the error name, wether the fallback function
 * should be used for the specified algorithm and method.
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The algorithm
 * @param {string} method The name of the method.
 * @param {*} reason The reason for the fail.
 * @returns {boolean} true if fallback function should be used, false otherwise
 */
function shouldFallBack(algorithm, method, reason) {
  
  var fallback = false;
  var algName = algorithm.name || algorithm;
  
  if(reason instanceof Error || reason instanceof DOMException) {
    var errorName = reason.name;
    var methodErrors = methodFallbackErrors[method];
    if(!methodErrors) {
      throw new NotSupportedError('Unkown method: ' + method);
    };

    fallback = (methodFallbackErrors['default'].indexOf(errorName) !== -1)
            || (methodErrors.indexOf(errorName) !== -1);  
    
  } else if(reason instanceof Object && reason.name) {
    // Edge return algorithm object on error. Always use fall back function.
    if(reason.name === algName) {
      fallback = true;
    };
    
  } else if(reason instanceof Event && reason.type && reason.type === 'error') {
    // IE return event with type "error" on error. Always use fall back 
    // function.
    fallback = true;
  };
  return fallback;
};

/**
 * Normalizes the algorithm given as parameter. <br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-normalize-an-algorithm}
 * 
 * @private
 * @param {string} op The operation for which the algorithm should be used. 
 * Possible values are "generateKey", "digest", "encrypt", "decrypt", "sign", 
 * "verify", "deriveBits", "importKey", "wrapKey" and "unwrapKey".
 * @param {AlgorithmIdentifier} alg The AlgorithmIdentifier.
 * @returns {Object} The normalized algorithm.
 */
function normalizeAlgorithm(op, alg) {
  if(isString(alg)) {
    return normalizeAlgorithm(op, {name: alg});
  } else {

    alg.name = alg.name.toUpperCase().replace('V','v');
    
    ensureOperation(op, alg);
    
    var normAlg;
    switch (alg.name) {
      case 'SHA-1':
      case 'SHA-256':
      case 'SHA-384':
      case 'SHA-512':
        normAlg = new Algorithm().init(alg);
        break;
      case 'AES-GCM':
        if(op === 'encrypt' || op === 'decrypt') {
          normAlg = new AesGcmParams().init(alg);
        } else if(op === 'generateKey' || op === 'getKeyLength') {
          // According to the W3C specification the operation getKeyLength 
          // requires 'AesDerivedKeyParams'. But 'AesKeyGenParams' and 
          // 'AesDerivedKeyParams' are identical.
          normAlg = new AesKeyGenParams().init(alg);
        } else if(op === 'importKey' || op === 'exportKey') {
          normAlg = new Algorithm().init(alg);
        } else {
          throw new NotSupportedError("Normalizing '" + alg.name 
                  + "' algorithm for op '" + op + "' not supported");
        }
        break;
      case 'RSA-OAEP':
        if(op === 'encrypt' || op === 'decrypt' 
                || op === 'wrapKey' || op === 'unwrapKey') {
          normAlg = new RsaOaepParams().init(alg);
        } else if(op === 'generateKey') {
          normAlg = new RsaHashedKeyGenParams().init(alg);
        } else if(op === 'importKey') {
          normAlg = new RsaHashedImportParams().init(alg);
        } else {
          throw new NotSupportedError("Normalizing '" + alg.name 
                  + "' algorithm for op '" + op + "' not supported");
        }
        break;
      case 'PBKDF2':
        if(op === 'importKey') {
          normAlg = new Algorithm().init(alg);
        } else if(op === 'deriveBits') {
          normAlg = new Pbkdf2Params().init(alg);
        } else {
          throw new NotSupportedError("Normalizing '" + alg.name 
                  + "' algorithm for op '" + op + "' not supported");
        }
        break;
    }
    return normAlg;
  }
}

/**
 * Checks if the the operation is supported by the algorithm.
 * 
 * @private
 * @param {string} operation The operation
 * @param {Algorithm|AlgorithmIdentifier} algorithm The algorithm
 * @returns {boolean} true if the operation is supported by the algorithm,
 * otherwise false
 */
function supportsOperation(operation, algorithm) {
  var algName = algorithm.name || algorithm;
  return !!algorithmFallbackOperations[operation][algName];
}

/**
 * Ensures that the specified operation is supported by the algorithm. If
 * operation is not supported a NotSupportedError will be thrown.
 * 
 * @private
 * @param {string} operation The operation
 * @param {Algorithm|AlgorithmIdentifier} algorithm The algorithm
 */
function ensureOperation(operation, algorithm) {
  var algName = algorithm.name || algorithm;
  if(!supportsOperation(operation, algorithm)) {
    throw new NotSupportedError("The operation '" + operation 
            + "' is not supported by algorithm '" 
            + algName+ "'");
  }
}

/**
 * Performs the specified operation on the given algorithm using the
 * arguments passed as parameter.
 * 
 * @private
 * @param {string} operation The operation to perform
 * @param {Algorithm} normalizedAlgorithm The algorithm with which the
 * opertion will be performed.
 * @param {Array} args The arguments for the operation
 * @returns {*} The result of the operation
 */
function performOperation(operation, normalizedAlgorithm, args) {
  ensureOperation(operation, normalizedAlgorithm);
  var operationFn = 
          algorithmFallbackOperations[operation][normalizedAlgorithm.name];
  return operationFn.apply(this, args);
}

/**
 * Wraps the given function in a Promise. If the given function is
 * asynchronous it have to return a Promise or an objekt with the
 * possibility to set <code>oncomplete</code> and <code>onerror</code>
 * functions. 
 * 
 * @private
 * @param {function} fn The function to be wrapped in a Promise
 * @returns {Promise} The Promise of the wrapped function
 */
function toPromise(fn) {
  
  return new Promise(function(resolve, reject) {
    var result = fn.call();
    if(typeof result.then === 'function') {
      result.then(function(res) {
        resolve(res);
      }).catch(function(error) {
        reject(error);
      });
    } else if('oncomplete' in result && 'onerror' in result) {
      result.oncomplete = function(evt) {resolve(evt.target.result);};
      result.onerror = function(error) {reject(error);};
    } else {
      resolve(result);
    }
  });
}

/**
 * Generates a digest from the hash function and data given as parameters.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {AlgorithmIdentifier} algorithm The hash function to use
 * @param {BufferSource} data The data to be hashed
 * @returns {Promise} A Promise that returns the hash as ArrayBuffer
 */
function digest(algorithm, data) {
  return new Promise(function(resolve, reject) {
    if(subtle) {
      toPromise(function() {return subtle.digest(algorithm, data);})
      .then(function(hash) {
        resolve(hash);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'digest', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    function fallback() {
      digestFallback(algorithm, data).then(function(hash) {
        resolve(hash);
      }).catch(function(err) {
        reject(err);
      });      
    }
  });
}

/**
 * Generates a digest from the hash function and data given as parameters.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-digest}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The hash function to use
 * @param {BufferSource} data The data to be hashed
 * @returns {ArrayBuffer} The hash as ArrayBuffer
 */
function digestFallback(algorithm, data) {
  return new Promise(function(resolve, reject) {
    data = cloneBufferSource(data);
    var normalizedAlgorithm = normalizeAlgorithm('digest', algorithm);
    var result = performOperation(
            'digest', normalizedAlgorithm, [normalizedAlgorithm, data]);
    resolve(result);
  });
}

/**
 * Returns a Promise of a newly generated CryptoKey, for symmetrical 
 * algorithms, or a CryptoKeyPair, containing two newly generated keys, 
 * for asymmetrical algorithm.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {AlgorithmIdentifier} algorithm The key generation function to use.
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {string[]} keyUsages Indicating what can be done with the newly 
 * generated key.
 * @returns {Promise} Promise that returns the generated key as a CryptoKey 
 * or a CryptoKeyPair.
 */
function generateKey(algorithm, extractable, keyUsages) {
  return new Promise(function(resolve, reject) {
    if(subtle) {
      toPromise(function() {
        return subtle.generateKey(algorithm, extractable, keyUsages);
      }).then(function(key) {
        if(isIE) {
          key.usages = keyUsages;
        };
        resolve(key);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'generateKey', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    function fallback() {
      generateKeyFallback(algorithm, extractable, keyUsages)
      .then(function(key) {
        
        if(subtle) {
          if(key instanceof CryptoKey) {
            // Single secret key
            
            polyToNativeCryptoKey(key).then(function(nativeKey) {
              resolve(nativeKey);
            }).catch(function() {
              resolve(key);
            });
          } else {
            // Pair of keys
            
            Promise.all([
              polyToNativeCryptoKey(key.privateKey),
              polyToNativeCryptoKey(key.publicKey)
            ]).then(function(nativeKeys) {
              resolve({
                privateKey: nativeKeys[0],
                publicKey: nativeKeys[1]
              });
            }).catch(function() {
              resolve(key);
            });
          }
        } else {
         resolve(key); 
        }
      }).catch(function(err) {
        reject(err);
      });
    }
  }); 
}

/**
 * Returns a Promise of a newly generated CryptoKey, for symmetrical 
 * algorithms, or a CryptoKeyPair, containing two newly generated keys, 
 * for asymmetrical algorithm.<br />
 * The CryptoKey or CryptoKeyPair is generated by using a fallback library.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-generateKey}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The key generation function to use.
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {String[]} keyUsages Indicating what can be done with the newly 
 * generated key.
 * @returns {Promise} Promise that returns the generated key as a CryptoKey 
 * or a pair of CryptoKey objects.
 */
function generateKeyFallback(algorithm, extractable, keyUsages) {
  return new Promise(function(resolve, reject) {
    
    var normAlgo = normalizeAlgorithm('generateKey', algorithm); 
    var result = performOperation(
            'generateKey', normAlgo, [normAlgo, extractable, keyUsages]);

    if(result instanceof CryptoKey) {
      if((result.type === 'secret' || result.type === 'private') 
              && keyUsages.length === 0) {
        throw new SyntaxError(
                "'keyUsages' can not be empty for secret or private key");
      }
    } else {
      // KeyPair
      if(!result.privateKey.usages || result.privateKey.usages.length === 0) {
        throw new SyntaxError('Private key usages can not be empty');
      }
    }
    resolve(result);
  });
}

/**
 * Returns a Promise of the key encrypted in the requested format.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-exportKey}
 * 
 * @memberOf module:webcrypto.subtle
 * @param {string} format The data format in which the key has to be exported.
 * @param {CryptoKey | Key} key The CryptoKey to export.
 * @returns {Promise} Promise that returns the key in the requested format.
 */
function exportKey(format, key) {
  if(isNativeCryptoKey(key)) {
    if(subtle) {
      // Not necessary to handle 'NotSupportedError' here, because if
      // export of native key is not supported, fallback function
      // has also no possibility to export it
      return toPromise(function() {
        return subtle.exportKey(format, key);
      }).then(function(keyData) {
        // IE exports JWK as ArrayBuffer
        if(isIE && format === 'jwk' && isBufferSource(keyData)) {
          keyData = JSON.parse(bytesToString(new Uint8Array(keyData)));
        };
        return keyData;
      });
    } else {
      return Promise.reject(new NotSupportedError(
        "'key' is native CryptoKey but native Crypto object not available"));
    }
  } else if(isPolyfillCryptoKey(key)) {
    // It is not useful to try to convert key to native key first and then
    // use native export method. The conversion to a native key would
    // also export the key first.
    return exportKeyFallback(format, key);
  } else {
    return Promise.reject(new DataError('Unknown format of "key"'));
  }
}

/**
 * Returns a Promise of the key encrypted in the requested format.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-exportKey}
 * 
 * @private
 * @param {string} format The data format in which the key has to be exported.
 * @param {CryptoKey} key The CryptoKey to export.
 * @returns {Promise} Promise that returns the key in the requested format.
 */
function exportKeyFallback(format, key) {
  // Called only with polyfill CryptoKey. See exportKey abvove.
  return new Promise(function(resolve, reject) {
    ensureOperation('exportKey', key.algorithm);
    if(!key.extractable) {
      throw new InvalidAccessError('Key is not extractable');
    }
    var result = performOperation('exportKey', key.algorithm, [format, key]);
    resolve(result);
  });
}

/**
 * Returns a Promise of the CryptoKey generated from the data given in
 * parameters.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {string} format The data format of the key to imported. Possible
 * values are "raw" (usually a secret key), "pkcs8" (private key), 
 * "skpi" (usually a public key) and "jwk".
 * @param {BufferSource | Object} keyData The key in the specified format.
 * @param {AlgorithmIdentifier} algorithm The cryptographic algorithm for use 
 * with the output key object.
 * @param {boolean} extractable indicating if the key can be extracted from the 
 * CryptoKey object at a later stage.
 * @param {string[]} usages Indicating what can be done with the key.
 * @returns {Promise} Promise that returns the generated CryptoKey.
 */
function importKey(format, keyData, algorithm, extractable, usages) {
  return new Promise(function(resolve, reject) {
    // TODO: Check if isNativeSupported()? Validate performance
    if(subtle) {
      toPromise(function() {
        return subtle.importKey(
                format, keyData, algorithm, extractable, usages);
      }).then(function(key) {
        if(isIE) {
          key.usages = usages;
        };
        resolve(key);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'importKey', err)) {
          setNativeUnsupported(
                  (algorithm.name || algorithm), 
                  'import', 
                  getKeyType(algorithm, format, keyData),
                  format);
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }

    function fallback() {
      importKeyFallback(format, keyData, algorithm, extractable, usages)
      .then(function(key) {
        if(subtle) {
          polyToNativeCryptoKey(key).then(function(nativeKey) {
            resolve(nativeKey);
          }).catch(function() {
            resolve(key);
          });
        } else {
          resolve(key);
        }
      }).catch(function(err) {
        reject(err);
      });
    };

  });
}


/**
 * Returns a Promise of the CryptoKey generated from the data given in
 * parameters.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-importKey}
 * 
 * @private
 * @param {string} format the data format of the key to imported. Possible
 * values are "raw" (usually a secret key), "pkcs8" (private key), 
 * "skpi" (usually a public key) and "jwk".
 * @param {BufferSource | Object} keyData The key in the specified format.
 * @param {AlgorithmIdentifier} algorithm The cryptographic algorithm for use 
 * with the output key object.
 * @param {boolean} extractable indicating if the key can be extracted from the 
 * CryptoKey object at a later stage.
 * @param {string[]} usages Indicating what can be done with the key.
 * @returns {Promise} Promise that returns the generated CryptoKey.
 */
function importKeyFallback(format, keyData, algorithm, extractable, usages) {
  return new Promise(function(resolve, reject) {
    var normAlgo = normalizeAlgorithm('importKey', algorithm);
    if(format === 'raw' || format === 'pkcs8' || format === 'spki') {
      if(isJWK(keyData)) {
        throw new TypeError("'keyData' is a JsonWebKey");
      }
      keyData = cloneBufferSource(keyData);
    } else if(format === 'jwk' && !isJWK(keyData)) {
      throw new TypeError("'keyData' is not a JsonWebKey");
    }
    
    var result = performOperation('importKey', normAlgo, 
            [format, keyData, normAlgo, extractable, usages]);
    
    if((result.type === 'secret' || result.type === 'private') 
        && usages.length === 0) {
      throw new SyntaxError("'usages' is empty");
    }
    // CryptoKey is readable only, create new key to change properties
    result = new CryptoKey(
            result.type, 
            extractable, 
            result.algorithm, 
            usages,
            result._handle);
    resolve(result);
  });
};

/**
 * Returns a Promise of the encrypted data corresponding to the 
 * data, algorithm and key given as parameters.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {AlgorithmIdentifier} algorithm The encryption function to use.
 * @param {CryptoKey} key The key to be used for the encryption.
 * @param {ArrayBuffer | ArrayBufferView} data The data to be encrypted.
 * @returns {Promise} A Promise that returns the ciphertext generated by 
 * the encryption of the data as an ArrayBuffer.
 */
function encrypt(algorithm, key, data) {
  return new Promise(function(resolve, reject) {
    if(subtle) {
      polyToNativeCryptoKey(key).then(function(nativeKey) {
        return toPromise(function() {
          return subtle.encrypt(algorithm, nativeKey, data);});
      }).then(function(ciphertext) {
        resolve(ciphertext);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'encrypt', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    
    function fallback() {
      nativeToPolyCryptoKey(key).then(function(polyKey) {
        return encryptFallback(algorithm, polyKey, data);
      }).then(function(ciphertext) {
        resolve(ciphertext);
      }).catch(function(err) {
        reject(err);
      });
    }
  });
}

/**
 * Returns a Promise of the encrypted data corresponding to the 
 * data, algorithm and key given as parameters.<br />
 * The encryption is done by using a fallback library.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-encrypt}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The encryption function to use.
 * @param {CryptoKey} key The key to be used for the encryption.
 * @param {ArrayBuffer | ArrayBufferView} data The data to be encrypted.
 * @returns {Promise} A Promise that returns the ciphertext generated by 
 * the encryption of the data as an ArrayBuffer.
 */
function encryptFallback(algorithm, key, data) {
  return new Promise(function(resolve, reject) {
    
    data = cloneBufferSource(data);
    var normalizedAlgorithm = normalizeAlgorithm('encrypt', algorithm);
    
    if(normalizedAlgorithm.name !== key.algorithm.name) {
      throw new InvalidAccessError('Key not usable with this algorithm');
    }
    if(key.usages.indexOf('encrypt') === -1) {
      throw new InvalidAccessError(
              'key.usages does not permit this operation');
    }
    
    var ciphertext = performOperation('encrypt', normalizedAlgorithm, 
            [normalizedAlgorithm, key, data]);
    resolve(ciphertext);
  });  
}

/**
 * Returns a Promise of the cleartext corresponding to the ciphertext, 
 * algorithm and key given as parameters.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {AlgorithmIdentifier} algorithm The encryption function to use.
 * @param {CryptoKey} key The key to be used for the decryption.
 * @param {ArrayBuffer | ArrayBufferView} data The data to be decrypted.
 * @returns {Promise} A Promise of the cleartext corresponding to the 
 * ciphertext, algorithm and key given as parameters.
 */
function decrypt(algorithm, key, data) {
  return new Promise(function(resolve, reject) {
    
    if(subtle) {
      polyToNativeCryptoKey(key).then(function(nativeKey) {
        return toPromise(function() {
          return subtle.decrypt(algorithm, key, data);});
      }).then(function(plaintext) {
        resolve(plaintext);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'decrypt', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    
    function fallback() {
      nativeToPolyCryptoKey(key).then(function(polyKey) {
        return decryptFallback(algorithm, polyKey, data);
      }).then(function(plaintext) {
        resolve(plaintext);
      }).catch(function(err) {
        reject(err);
      });
    };
  });
}

/**
 * Returns a Promise of the cleartext corresponding to the ciphertext, 
 * algorithm and key given as parameters.<br />
 * The decryption is done by using a fallback library.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-decrypt}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The encryption function to use.
 * @param {CryptoKey} key The key to be used for the decryption.
 * @param {ArrayBuffer | ArrayBufferView} data The data to be decrypted.
 * @returns {Promise} A Promise of the cleartext corresponding to the 
 * ciphertext, algorithm and key given as parameters.
 */
function decryptFallback(algorithm, key, data) {
  return new Promise(function(resolve, reject) {
    
    data = cloneBufferSource(data);
    var normalizedAlgorithm = normalizeAlgorithm('decrypt', algorithm);
    
    if(normalizedAlgorithm.name !== key.algorithm.name) {
      throw new InvalidAccessError('Key not usable with this algorithm');
    } 
    if(key.usages.indexOf('decrypt') === -1) {
      throw new InvalidAccessError(
              'key.usages does not permit this operation');
    }
    var plaintext = performOperation('decrypt', normalizedAlgorithm, 
            [normalizedAlgorithm, key, data]);
    resolve(plaintext);
  });  
}

/**
 * Returns a Promise of an ArrayBuffer containing the key material of key, 
 * encrypted with wrappingKey using the specified wrapAlgorithm.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {string} format The format in which the key should be exported
 * @param {CryptoKey} key The key to be wrapped
 * @param {CryptoKey} wrappingKey The key to perform the wrapping
 * @param {AlgorithmIdentifier} wrapAlgorithm The algorithm used to perform 
 * the wrapping
 * @returns {Promise} A Promise of an ArrayBuffer containing the key material 
 * of key, encrypted with wrappingKey using the specified wrapAlgorithm
 */
function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
  return new Promise(function(resolve, reject) {
    if(subtle) {
      Promise.all([
        polyToNativeCryptoKey(key),
        polyToNativeCryptoKey(wrappingKey)
      ]).then(function(nativeKeys) {
        if(isW3C) {
          return toPromise(function() {
            return subtle.wrapKey(
                    format, nativeKeys[0], nativeKeys[1], wrapAlgorithm);
          });
        } else {
          return exportKey(format, nativeKeys[0]).then(function(expKey) {
            var bytes;
            if(format === 'jwk') {
              bytes = jwkToBytes(expKey);
            } else {
              bytes = expKey;
            };
            return encrypt(wrapAlgorithm, nativeKeys[1], bytes);            
          });
        }
      }).then(function(wrappedKey) {
        resolve(wrappedKey);
      }).catch(function(err) {
        if(shouldFallBack(wrapAlgorithm, 'wrapKey', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    
    function fallback() {
     Promise.all([
        nativeToPolyCryptoKey(key),
        nativeToPolyCryptoKey(wrappingKey)
     ]).then(function(polyKeys) {
       return wrapKeyFallback(format, polyKeys[0], polyKeys[1], wrapAlgorithm);
     }).then(function(wrappedKey) {
        resolve(wrappedKey);
     }).catch(function(err) {
       reject(err);
     });
    }
    
  });
}

/**
 * Returns a Promise of an ArrayBuffer containing the key material of key, 
 * encrypted with wrappingKey using the specified wrapAlgorithm.<br />
 * The opertaion is done by using a fallback library.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-wrapKey}
 * 
 * @private
 * @param {string} format The format in which the key should be exported
 * @param {CryptoKey} key The key to be wrapped
 * @param {CryptoKey} wrappingKey The key to perform the wrapping
 * @param {AlgorithmIdentifier} wrapAlgorithm The algorithm used to perform 
 * the wrapping
 * @returns {Promise} A Promise of an ArrayBuffer containing the key material 
 * of key, encrypted with wrappingKey using the specified wrapAlgorithm
 */
function wrapKeyFallback(format, key, wrappingKey, wrapAlgorithm) {
  
  // TODO: Use native encrypt as fallback?
  
  return new Promise(function(resolve, reject) {
    
    try {
      var algorithm = wrapAlgorithm;
      var op = 'wrapKey';
      var normalizedAlgorithm = normalizeAlgorithm(op, algorithm);
    } catch(wrapErr) {
      var op = 'encrypt';
      normalizedAlgorithm = normalizeAlgorithm(op, algorithm);
    }    
    ensureOperation(op, normalizedAlgorithm);
    if(normalizedAlgorithm.name !== wrappingKey.algorithm.name) {
      throw new InvalidAccessError('Key not usable with this algorithm');
    }
    if(wrappingKey.usages.indexOf('wrapKey') === -1) {
      throw new InvalidAccessError(
              'wrappingKey.usages does not permit this operation');
    }
    ensureOperation('exportKey', key.algorithm);
    if(!key.extractable) {
      throw new InvalidAccessError("'key' is not extractable");
    }

    var expKey = performOperation('exportKey', key.algorithm, [format, key]);

    var bytes;
    if(format === 'jwk') {
      bytes = jwkToBytes(expKey);
    } else {
      bytes = expKey;
    }
    
    var result;
    if(supportsOperation('wrapKey', normalizedAlgorithm)) {
      result = performOperation('wrapKey', normalizedAlgorithm, 
              [normalizedAlgorithm, wrappingKey, bytes]);
    } else if(supportsOperation('encrypt', normalizedAlgorithm)) {
      result = performOperation('encrypt', normalizedAlgorithm, 
              [normalizedAlgorithm, wrappingKey, bytes]);     
    } else {
      throw new NotSupportedError(
              "The operation is not supported by algorithm '" 
              + normalizedAlgorithm.name + "'");
    }

    resolve(result);

  });
};

/**
 * Returns a Promise of a CryptoKey corresponding to the wrapped key given 
 * in parameter.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {string} format The format of the wrapped key
 * @param {BufferSource} wrappedKey The key which should be unwrapped
 * @param {CryptoKey} unwrappingKey The key to perform the unwrapping
 * @param {AlgorithmIdentifier} unwrapAlgorithm The algorithm used to perform 
 * the unwrapping
 * @param {AlgorithmIdentifier} unwrappedKeyAlgorithm The algorithm of the 
 * wrapped key
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {string[]} keyUsages Indicating what can be done with the unwrapped
 * key
 * @returns {Promise} Promise of a CryptoKey corresponding to the wrapped key
 * given in parameter
 */
function unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
      unwrappedKeyAlgorithm, extractable, keyUsages) {
  return new Promise(function(resolve, reject) {
    if(subtle) {
      polyToNativeCryptoKey(unwrappingKey).then(function(nativeUnwrappingKey) {
        if(isW3C) {
          return toPromise(function() {
            return subtle.unwrapKey(
                    format, wrappedKey, nativeUnwrappingKey, 
                    unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, 
                    keyUsages)
          });
        } else {
          // IE does not support unwrapKey
          return decrypt(unwrapAlgorithm, nativeUnwrappingKey, wrappedKey)
          .then(function(keyData) {
            if(format === 'jwk') {
              keyData = bytesToJwk(new Uint8Array(keyData));
            };
            return importKey(format, keyData, unwrappedKeyAlgorithm, 
                    extractable, keyUsages);
          });
        }
      }).then(function(unwrappedKey) {
        resolve(unwrappedKey);
      }).catch(function(err) {
        if(shouldFallBack(unwrapAlgorithm, 'unwrapKey', err)) {
          fallback();
        } else { 
          reject(err);
        }
      });
    } else {
      fallback();
    }
    
    function fallback() {
      nativeToPolyCryptoKey(unwrappingKey).then(function(polyUnwrappingKey) {
        return unwrapKeyFallback(format, wrappedKey, polyUnwrappingKey, 
                unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages);
      }).then(function(unwrappedKey) {
        if(subtle) {
          polyToNativeCryptoKey(unwrappedKey).then(function(nativeUnwrappedKey) {
            resolve(nativeUnwrappedKey);
          }).catch(function() {
            resolve(unwrappedKey);
          });
        } else {
          resolve(unwrappedKey);
        }
      }).catch(function(err) {
        reject(err);
      });
    };
    
  });
}

/**
 * Returns a Promise of a CryptoKey corresponding to the wrapped key given 
 * in parameter.<br />
 * The opertaion is done by using a fallback library.
 * 
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-unwrapKey}
 * @private
 * @param {string} format The format of the wrapped key
 * @param {BufferSource} wrappedKey The key which should be unwrapped
 * @param {CryptoKey} unwrappingKey The key to perform the unwrapping
 * @param {AlgorithmIdentifier} unwrapAlgorithm The algorithm used to perform 
 * the unwrapping
 * @param {AlgorithmIdentifier} unwrappedKeyAlgorithm The algorithm of the 
 * wrapped key
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {string[]} keyUsages Indicating what can be done with the unwrapped
 * key
 * @returns {Promise} Promise of a CryptoKey corresponding to the wrapped key
 * given in parameter
 */
function unwrapKeyFallback(format, wrappedKey, unwrappingKey, unwrapAlgorithm,
      unwrappedKeyAlgorithm, extractable, keyUsages) {

  // TODO: Use native decrypt as fallback?
  
  return new Promise(function(resolve, reject) {
    
    var algorithm = unwrapAlgorithm;
    var usages = keyUsages;
    wrappedKey = cloneBufferSource(wrappedKey);
    try {
      var normalizedAlgorithm = normalizeAlgorithm('unwrapKey', algorithm);
    } catch(err) {
      normalizedAlgorithm = normalizeAlgorithm('decrypt', algorithm);
    }
    var normalizedKeyAlgorithm = normalizeAlgorithm(
            'importKey', unwrappedKeyAlgorithm);    
    
    if(normalizedAlgorithm.name !== unwrappingKey.algorithm.name) {
      throw new InvalidAccessError('Key not usable with this algorithm');
    }
    if(unwrappingKey.usages.indexOf('unwrapKey') === -1) {
      throw new InvalidAccessError(
              'unwrappingKey.usages does not permit this operation');
    }
    
    var key;
    if(supportsOperation('unwrapKey', normalizedAlgorithm)) {
      key = performOperation('unwrapKey', normalizedAlgorithm, 
              [normalizedAlgorithm, unwrappingKey, wrappedKey]);
    } else if(supportsOperation('decrypt', normalizedAlgorithm)) {
      key = performOperation('decrypt', normalizedAlgorithm, 
              [normalizedAlgorithm, unwrappingKey, wrappedKey]);
    } else {
      throw new NotSupportedError(
              "The operation is not supported by algorithm '" 
              + normalizedAlgorithm.name + "'");
    }
    
    var bytes;
    if(format === 'jwk') {
      bytes = bytesToJwk(new Uint8Array(key));
    } else {
      bytes = key;
    }
    var result = performOperation('importKey', normalizedKeyAlgorithm, 
            [format, bytes, normalizedKeyAlgorithm, extractable, usages]);
    
    if((result.type === 'secret' || result.type === 'private') 
            && (!usages.length || usages.length === 0)) {
      throw new SyntaxError("'usages' is empty");
    }
    
    result = new CryptoKey(result.type, extractable, result.algorithm, 
            usages, result._handle);
    resolve(result);
  });
}

/**
 * Generates a new CryptoKey derivated from a master key and a specific 
 * algorithm given as parameters.
 * 
 * @memberOf module:webcrypto.subtle
 * @param {AlgorithmIdentifier} algorithm The algorithm identifier defining 
 * the derivation algorithm to use.
 * @param {CryptoKey} baseKey The base key to be used by the key derivation 
 * algorithm.
 * @param {AlgorithmIdentifier} derivedKeyType The algorithm the derived key 
 * will be used for.
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {string[]} keyUsages Indicating what can be done with the derivated 
 * key
 * @returns {Promise} A Promise that returns the newly created CryptoKey.
 */
function deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
  
  return new Promise(function(resolve, reject) {
    
    // deriveKey is not supported in IE
    if(isW3C && subtle) {
      polyToNativeCryptoKey(baseKey).then(function(nativeBaseKey) {
        return toPromise(function() {
          return subtle.deriveKey(algorithm, nativeBaseKey, derivedKeyType, 
                extractable, keyUsages)
        });
      }).then(function(key) {
        resolve(key);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'deriveKey', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    
    function fallback() {
      nativeToPolyCryptoKey(baseKey).then(function(polyBaseKey) {
        return deriveKeyFallback(algorithm, polyBaseKey, derivedKeyType, 
                extractable, keyUsages);
      }).then(function(key) {
        if(subtle) {
          polyToNativeCryptoKey(key).then(function(nativeKey) {
            resolve(nativeKey);
          }).catch(function() {
            resolve(key);
          });
        } else {
          resolve(key);
        }
      }).catch(function(err) {
        reject(err);
      });
    }
  });
};

/**
 * Generates a new CryptoKey derivated from a master key and a specific 
 * algorithm given as parameters.<br />
 * The opertaion is done by using a fallback library.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-deriveKey}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The algorithm identifier defining 
 * the derivation algorithm to use.
 * @param {CryptoKey} baseKey The base key to be used by the key derivation 
 * algorithm.
 * @param {AlgorithmIdentifier} derivedKeyType The algorithm the derived key 
 * will be used for.
 * @param {boolean} extractable Indicating if the key can be extracted from 
 * the CryptoKey object at a later stage.
 * @param {string[]} keyUsages Indicating what can be done with the derivated 
 * key
 * @returns {Promise} A Promise that returns the newly created CryptoKey.
 */
function deriveKeyFallback(
        algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
  
  return new Promise(function(resolve, reject) {
    
    var usages = keyUsages;
    var normalizedAlgorithm = normalizeAlgorithm('deriveBits', algorithm);
    
    // This is not as specified in the W3C spefification. The specification
    // says to use operation 'importKey' here. For normalizing with
    // the operation 'importKey' its sufficient if 'derivedKeyTyp' contains
    // the name of the algorithm.
    // But 'derivedKeyType' must contain the 'length' additionally. So here
    // is normalized with the operation 'getKeyLength'. 'getKeyLength' requires
    // the name of the algorithm and the length of the key.
    // http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-deriveKey
    var normalizedDerivedKeyAlgorithm = normalizeAlgorithm(
            'getKeyLength', derivedKeyType);    
    
    ensureOperation('deriveBits', normalizedAlgorithm);
    ensureOperation('getKeyLength', normalizedDerivedKeyAlgorithm);
    
    if(normalizedAlgorithm.name !== baseKey.algorithm.name) {
      throw new InvalidAccessError('Key not usable with this algorithm');
    }
    
    if(baseKey.usages.indexOf('deriveKey') === -1) {
      throw new InvalidAccessError(
              'baseKey.usages does not permit this operation');
    }
    
    var length = performOperation('getKeyLength', 
            normalizedDerivedKeyAlgorithm, 
            [normalizedDerivedKeyAlgorithm]);
    
    var secret = performOperation('deriveBits', normalizedAlgorithm, 
            [normalizedAlgorithm, baseKey, length]);
    
    var result = performOperation('importKey', normalizedDerivedKeyAlgorithm, 
        ['raw', secret, normalizedDerivedKeyAlgorithm, extractable, usages]);
    
    if((result.type === 'secret' || result.type === 'private') 
            && (!usages.length || usages.length === 0)) {
      throw new SyntaxError("'usages' is empty");
    }
    
    // Set extractable and usages here is not specified in the W3C 
    // spefification, but it is done nowhere else in the used operations.
    result = new CryptoKey(result.type, extractable, result.algorithm, usages, 
            result._handle);
    
    resolve(result);
  });
};

/**
 * Generates a new BufferSource of Bits derived from a master key and a 
 * specific algorithm given as parameters.<br />
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-deriveBits}
 * 
 * @memberOf module:webcrypto.subtle
 * @param {AlgorithmIdentifier} algorithm The algorithm identifier defining 
 * the derivation algorithm to use.
 * @param {CryptoKey} baseKey The base key to be used by the key derivation 
 * algorithm.
 * @param {number} length The length, in bits, of the generated BufferSource.
 * @returns {Promise} A Promise that returns the generated BufferSource.
 */
function deriveBits(algorithm, baseKey, length) {
  return new Promise(function(resolve, reject) {
    // deriveBits is not supported in IE
    if(isW3C && subtle) {
      return toPromise(function() {
        return subtle.deriveBits(algorithm, baseKey, length);
      }).then(function(bits) {
        resolve(bits);
      }).catch(function(err) {
        if(shouldFallBack(algorithm, 'deriveBits', err)) {
          fallback();
        } else {
          reject(err);
        }
      });
    } else {
      fallback();
    }
    
    function fallback() {
      nativeToPolyCryptoKey(baseKey).then(function(polyBaseKey) {
        return deriveBitsFallback(algorithm, polyBaseKey, length);
      }).then(function(result) {
        resolve(result);
      }).catch(function(err) {
        reject(err);
      });
    };
    
  });
}

/**
 * Generates a new BufferSource of Bits derived from a master key and a 
 * specific algorithm given as parameters.<br />
 * The opertaion is done by using a fallback library.
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-deriveBits}
 * 
 * @private
 * @param {AlgorithmIdentifier} algorithm The algorithm identifier defining 
 * the derivation algorithm to use.
 * @param {CryptoKey} baseKey The base key to be used by the key derivation 
 * algorithm.
 * @param {number} length The length, in bits, of the generated BufferSource.
 * @returns {Promise} A Promise that returns the generated BufferSource.
 */
function deriveBitsFallback(algorithm, baseKey, length) {
  return new Promise(function(resolve, reject) {
    var normalizedAlgorithm = normalizeAlgorithm('deriveBits', algorithm);
    if(normalizedAlgorithm.name !== baseKey.algorithm.name) {
      throw new InvalidAccessError('Key not usable with this algorithm');
    }
    
    if(baseKey.usages.indexOf('deriveBits') === -1) {
      throw new InvalidAccessError(
              'baseKey.usages does not permit this operation');
    }
    
    var result = performOperation('deriveBits', normalizedAlgorithm, 
            [normalizedAlgorithm, baseKey, length]);
            
    resolve(result);
  });
}
/**
 * The util namespace contains some utility functions.
 * @memberOf module:webcrypto
 * @namespace util
 */
exports.util = {};
exports.util.bytesToBase64URL = bytesToBase64URL;
exports.util.base64URLToBytes = base64URLToBytes;
exports.util.bytesToHex = bytesToHex;
exports.util.hexToBytes = hexToBytes;
exports.util.stringToBytes = stringToBytes;
exports.util.bytesToString = bytesToString;
exports.util.blobToBytes = blobToBytes;
exports.util.bytesToBlob = bytesToBlob;
exports.util.blobToBytesSync = blobToBytesSync;
exports.util.bytesToBlobSync = bytesToBlobSync;
/**
 * Creates inheritance.
 * 
 * @private
 * @param {function} base The base class / parent.
 * @param {function} sub The subclass / child.
 */
function extend(base, sub) {
    var origSubProto = sub.prototype;
    sub.prototype = Object.create(base.prototype);
    for(var key in origSubProto) {
        sub.prototype[key] = origSubProto[key];
    }
    Object.defineProperty(sub.prototype, 'constructor', { 
      enumerable: false, 
      value: sub 
    });
    sub._super = base.prototype;
}


/**
 * Converts the string given as parameter to ByteArray.
 * 
 * @memberOf module:webcrypto.util
 * @param {string} str The string to be converted
 * @param {boolean} [utf8=false] Indicates if the resulting ByteArray
 * should be encoded in UTF-8. If not, it should be ensured that the numeric
 * unicode of each character in <code>str</code> is in the range of 0 to 255.
 * @returns {ByteArray} The string as ByteArray
 */
function stringToBytes(str, utf8) {
  var bytes;
  if(utf8 && global.TextEncoder) {
    var encoder = new TextEncoder('utf-8');
    bytes = encoder.encode(str);
  } else {
    bytes = asmCrypto.string_to_bytes(str, utf8);
    bytes = new Uint8Array(bytes.buffer.slice(0, bytes.length));
  }
  return bytes;
}

/**
 * Converts the ByteArray given as parameter to string.
 * 
 * @memberOf module:webcrypto.util
 * @param {ByteArray} bytes The ByteArray to be converted
 * @param {boolean} [utf8=false] Indicates if the ByteArray is encoded in
 * UTF-8.
 * @returns {string} The ByteArray as string
 */
function bytesToString(bytes, utf8) {
  var str;
  if(global.TextDecoder && utf8) {
    var decoder = new TextDecoder('utf-8', {fatal: true});
    str = decoder.decode(bytes);
  } else {
    str = asmCrypto.bytes_to_string(bytes, utf8);
  }
  return str;
}

/**
 * Encodes the given bytes to Base64URL format.
 * 
 * @memberOf module:webcrypto.util
 * @param {ByteArray} bytes The array of bytes.
 * @returns {string} The bytes given as parameter as Base64URL encoded string.
 */
function bytesToBase64URL(bytes) {  
  var base64 = btoa(bytesToString(bytes));
  // Remove padding equal characters and replace characters according to 
  // base64url specifications
  return base64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Encodes the given Base64URL string to a byte array.
 * 
 * @memberOf module:webcrypto.util
 * @param {string} str Base64URL encodes string
 * @returns {ByteArray}
 */
function base64URLToBytes(str) {
  if(str.length % 4 === 2) {
    str = str + '==';
  } else if(str.length % 4 === 3) {
    str = str + '=';
  }
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  return stringToBytes(atob(str));
}

/**
 * Converts the given ByteArray to a string in hexadecimal format.
 * 
 * @memberOf module:webcrypto.util
 * @param {ByteArray} bytes The bytes to be converted
 * @returns {string} The bytes given as parameter as string in hexadecimal 
 * format.
 */
function bytesToHex(bytes) {
  var str = '';
  var i = 0;
  var len = bytes.length;
  while(i < len) {
    var byte = bytes[i];
    var hex = byte.toString(16);
    if(byte < 16) {
      hex = '0' + hex;
    }
    str += hex;
    i++;
  }
  return str;
}

/**
 * Converts the given string in hexadecimal format to ByteArray.
 * 
 * @memberOf module:webcrypto.util
 * @param {string} hex The string in hexadecimal format to be converted
 * @returns {ByteArray} The string given as paramter as ByteArray
 */
function hexToBytes(hex) {
  var length = hex.length;
  if(length & 1) {
    // If length is odd, add leading zero
    hex = '0' + hex;
    length++;
  }
  var bytes = new Uint8Array(length / 2);
  for(var i = 0; i < length; i += 2) {
    bytes[i/2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
};

/**
 * Converts the contents of the specified Blob or File to a ByteArray.
 * 
 * @memberOf module:webcrypto.util
 * @param {Blob|File} blob The Blob or File to convert into the ByteArray.
 * @returns {Promise} A Promise that is resolved at success with the ByteArray,
 * otherwise with an error.
 */
function blobToBytes(blob) {
  return new Promise(function(resolve, reject) {
    
    var reader = new FileReader();
    
    reader.onload = function(evt) {
      resolve(new Uint8Array(evt.target.result));
    };
    
    reader.onerror = function(evt) {
      reject(evt.target.error);
    };
    
    reader.readAsArrayBuffer(blob);
    
  });
};

/**
 * Converts the contents of the specified Blob or File to a ByteArray.<br />
 * <b>Note: </b> Since the function uses the FileReaderSync interfaces, it will
 * only run inside a WebWorker.
 * 
 * @memberOf module:webcrypto.util
 * @param {Blob|File} blob The Blob or File to convert into the ByteArray.
 * @returns {ByteArray} A ByteArray containing the contents of the blob or file.
 */
function blobToBytesSync(blob) {
  var fileReader = new FileReaderSync();
  return new Uint8Array(fileReader.readAsArrayBuffer(blob));
};

/**
 * Converts the specified ByteArray into a Blob.
 * 
 * @memberOf module:webcrypto.util
 * @param {ByteArray|BufferSource} bytes The bytes to put inside the blob.
 * @param {string} [type=""] The MIME type of the content of the ByteArray that
 * will be put in the blob.
 * @returns {Promise} A Promise that is resolved at success with the Blob,
 * otherwise with an error.
 */
function bytesToBlob(bytes, type) {
  return new Promise(function(resolve, reject) {
    resolve(bytesToBlobSync(bytes, type));
  });
};

/**
 * Converts the specified ByteArray into a Blob.
 * 
 * @memberOf module:webcrypto.util
 * @param {ByteArray|BufferSource} bytes The bytes to put inside the blob.
 * @param {string} [type=""] The MIME type of the content of the ByteArray that
 * will be put in the blob.
 * @returns {Blob} The blob containing the contents of the bytes.
 */
function bytesToBlobSync(bytes, type) {
  var blob;
  if(type) {
    blob = new Blob([bytes], {type: type});
  } else {
    blob = new Blob([bytes]);
  };
  return blob;
};


/**
 * Converts JWK to ByteArray.
 * 
 * @private
 * @param {object} jwk The JSON Web Key
 * @returns {ByteArray} JWK as ByteArray
 */
function jwkToBytes(jwk) {
  return stringToBytes(JSON.stringify(jwk), true);
}

/**
 * Converts ByteArray to JSON Web Key.
 * 
 * @private
 * @param {ByteArray} bytes The bytes to convert
 * @returns {object} The JSON Web Key
 */
function bytesToJwk(bytes) {
  var jwk;
  try {
    var errorMsg = 'JWK could not be parsed. Invalid data format';
    jwk = JSON.parse(bytesToString(bytes, true));
  } catch(err) {
    throw new DataError(errorMsg);
  }
  if(!isJWK(jwk)) {
    throw new DataError(errorMsg);
  };
  return jwk;
}

/**
 * Checks if the "arr" array contains other values then the "contains" array.
 * 
 * @private
 * @param {Array} arr The array which will be checked
 * @param {Array} contains The values which will be checked
 * @returns {boolean} true if "arr" contains other values then the "contains" 
 * array.
 */
function arrayContainsOther(arr, contains) {
  var containsOther = false;
  var i = 0;
  while(!containsOther && i < arr.length) {
    if(contains.indexOf(arr[i]) === -1) {
      containsOther = true;
    }
    i++;
  }
  return containsOther;
}

/**
 * Returns a new array containing the intersection of the two arrays given
 * as parameters.
 * 
 * @private
 * @param {Array} a Array A
 * @param {Array} b Array B
 * @returns {Array} Intersection of array a and array b.
 */
function arrayIntersect(a, b) {
  return a.filter(function(value) {
    return b.indexOf(value) !== -1;
  });
}

/**
 * Checks if the passed object is a JSON Web Key.
 * 
 * @private
 * @param {*} obj The object to check
 * @returns {boolean} true if the passed object is a JSON Web Key, otherwise 
 * false.
 */
function isJWK(obj) {
  return (obj && typeof obj === "object" && obj.kty);
}

/**
 * Checks if the passed object is a BufferSource.<br />
 * 
 * @private
 * @param {*} obj The object to check
 * @returns {boolean} true if obj is BufferSource, otherwise false
 */
function isBufferSource(obj) {
  return global.ArrayBuffer 
          && (obj instanceof ArrayBuffer || ArrayBuffer.isView(obj));
}

/**
 * Returns the ArrayBuffer from then given BufferSource.
 * 
 * @private
 * @param {BufferSource} bufferSource The BufferSource
 * @returns {ArrayBuffer} The ArrayBuffer from the given BufferSource
 */
function getBuffer(bufferSource) {
  var buffer;
  if(!isBufferSource(bufferSource)) {
    throw new TypeError('"bufferSource" is not of type BufferSource');
  }
  if(bufferSource instanceof ArrayBuffer) {
    buffer = bufferSource;
  } else {
    buffer = bufferSource.buffer;
  }
  return buffer;
}

/**
 * Returns the cloned data given as parameter.
 * 
 * @private
 * @param {BufferSource} data The data to be cloned
 * @returns {ArrayBuffer} The cloned data
 */
function cloneBufferSource(data) {
  if(global.ArrayBuffer && data instanceof ArrayBuffer) {
    return data.slice(0, data.byteLength);
  } else if(global.ArrayBuffer && ArrayBuffer.isView(data)) {
    return data.buffer.slice(
            data.byteOffset, (data.byteOffset + data.byteLength));
  } else {
    throw new TypeError('"data" is not of type ArrayBuffer or ArrayBufferView');
  }
}

/**
 * Checks if the value given as parameter is a string.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is a string, otherwise false
 */
function isString(value) {
  return (typeof value === 'string')
}

/**
 * Checks if the value given as parameter is a number.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is a number, otherwise false
 */
function isNumber(value) {
  return (typeof value === 'number');
}

/**
 * Checks if the value given as parameter is an object.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is an object, otherwise false
 */
function isObject(value) {
  return (typeof value === 'object');
}

/**
 * Checks if the value given as parameter is a BigInteger.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is a BigInteger, otherwise false
 */
function isBigInteger(value) {
  return (value instanceof Uint8Array)
}

/**
 * Checks if the value given as parameter is a ByteArray.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is a ByteArray, otherwise false
 */
function isByteArray(value) {
  return (value instanceof Uint8Array);
}

/**
 * Checks if the value given as parameter is a AlgorithmIdentifier.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is a AlgorithmIdentifier, otherwise false
 */
function isAlgorithmIdentifier(value) {
  return (isString(value) || isObject(value));
}

/**
 * Checks if the value given as parameter is a HashAlgorithmIdentifier.
 * 
 * @private
 * @param {*} value The value to be checked
 * @returns {boolean} True is value is a HashAlgorithmIdentifier, otherwise
 * false
 */
function isHashAlgorithmIdentifier(value) {
  return isAlgorithmIdentifier(value);
}

/**
 * Checks is the value given es parameter is native CryptoKey.
 * 
 * @private
 * @param {*} key The key to be checked
 * @returns {boolean} True is key is a native CryptoKey, otherwise false
 */
function isNativeCryptoKey(key) {
  return (global.CryptoKey && (key instanceof global.CryptoKey)) 
          || (global.Key && (key instanceof Key));
}

/**
 * Checks is the value given es parameter is polyfill CryptoKey.
 * 
 * @private
 * @param {*} key The key to be checked
 * @returns {boolean} True is key is a polyfill CryptoKey, otherwise false
 */
function isPolyfillCryptoKey(key) {
  var isPolyKey = false;
  if(key instanceof exports.CryptoKey) {
    isPolyKey = true;
    
  } else if(isObject(key) 
          && key.hasOwnProperty('type') 
          && key.hasOwnProperty('extractable')
          && key.hasOwnProperty('algorithm')
          && key.hasOwnProperty('usages')
          && key.hasOwnProperty('_handle')) {
    isPolyKey = true;
  };
  return isPolyKey;
};
!function() {
  if(!global.NotSupportedError) {
    function NotSupportedError(message) {
      var error = Error.apply(this, arguments);
      this.name = 'NotSupportedError';
      this.message = error.message;
      this.stack = error.stack;
    }
    NotSupportedError.prototype = Object.create(Error.prototype);
    NotSupportedError.prototype.constructor = NotSupportedError;
    global.NotSupportedError = NotSupportedError;
  };
  
  if(!global.InvalidAccessError) {
    function InvalidAccessError(message) {
      var error = Error.apply(this, arguments);
      this.name = 'InvalidAccessError';
      this.message = error.message;
      this.stack = error.stack;
    }
    InvalidAccessError.prototype = Object.create(Error.prototype);
    InvalidAccessError.prototype.constructor = InvalidAccessError;
    global.InvalidAccessError = InvalidAccessError;
  };
  
  if(!global.DataError) {
    function DataError(message) {
      var error = Error.apply(this, arguments);
      this.name = 'DataError';
      this.message = error.message;
      this.stack = error.stack;
    }
    DataError.prototype = Object.create(Error.prototype);
    DataError.prototype.constructor = DataError;
    global.DataError = DataError;
  };
  
  if(!global.OperationError) {
    function OperationError(message) {
      var error = Error.apply(this, arguments);
      this.name = 'OperationError';
      this.message = error.message;
      this.stack = error.stack;
    }
    OperationError.prototype = Object.create(Error.prototype);
    OperationError.prototype.constructor = OperationError;
    global.OperationError = OperationError;
  };
  
}();
!function() {
  if(!global.Promise && global.ES6Promise) {
    ES6Promise.polyfill();
  }
}();
/**
 * An AlgorithmIdentifier object used to specify an algorithm.
 * @memberOf module:webcrypto
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-AlgorithmIdentifier}
 * @typedef {(object|DOMString)} AlgorithmIdentifier
 */

/**
 * An HashAlgorithmIdentifier object used to specify an hash algorithm.
 * @memberOf module:webcrypto
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-HashAlgorithmIdentifier}
 * @typedef {AlgorithmIdentifier} HashAlgorithmIdentifier
 */

/**
 * The ArrayBufferView typedef is used to represent objects that provide a 
 * view on to an ArrayBuffer.
 * @memberOf module:webcrypto
 * @see {@link http://heycam.github.io/webidl/#common-ArrayBufferView}
 * @typedef {Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array
 * |Uint32Array|Uint8ClampedArray|Float32Array|Float64Array
 * |DataView} ArrayBufferView
 */

/**
 * The BufferSource typedef is used to represent objects that are either 
 * themselves an ArrayBuffer or which provide a view on to an ArrayBuffer.
 * @memberOf module:webcrypto
 * @see {@link http://heycam.github.io/webidl/#common-BufferSource}
 * @typedef {(ArrayBufferView|ArrayBuffer)} BufferSource 
 */

/**
 * The BigInteger typedef is a Uint8Array that holds an arbitrary magnitude 
 * unsigned integer in big-endian order.
 * @memberOf module:webcrypto
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-BigInteger}
 * @typedef {Uint8Array} BigInteger
 */

/**
 * The ByteArray typedef is used to represent an Array of Bytes, which
 * are represented by numbers from 0 to 255.
 * @memberOf module:webcrypto
 * @see {@link http://www.w3.org/TR/WebCryptoAPI/#dfn-BigInteger}
 * @typedef {Uint8Array} ByteArray
 */

/**
 * The CryptoKeyPair represents an asymmetric key pair that is comprised of 
 * both public and private keys.
 * @memberOf module:webcrypto
 * @typedef {Object} CryptoKeyPair
 * @property {module:webcrypto.CryptoKey} publicKey The public key
 * @property {module:webcrypto.CryptoKey} privateKey The private key
 */
return exports;
}));
//# sourceMappingURL=web-crypto.js.map