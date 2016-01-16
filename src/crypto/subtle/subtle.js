var algorithmOperations = {
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
    'AES-KW': exportKey_AES
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
  'deriveBits': [],
  'importKey': [],
  'exportKey': [],
  'wrapKey': [],
  'unwrapKey': []
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
 * should be used for the specified method.
 * 
 * @private
 * @param {string} method The name of the method.
 * @param {string} errorName The name ot the error.
 * @returns {boolean} true if fallback function should be used, false otherwise
 */
function shouldFallBack(method, errorName) {
  
  var methodErrors = methodFallbackErrors[method];
  if(!methodErrors) {
    throw new NotSupportedError('Unkown method: ' + method);
  };
  
  return (methodFallbackErrors['default'].indexOf(errorName) !== -1)
          || (methodErrors.indexOf(errorName) !== -1);
  
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

    var algName = alg.name.toUpperCase().replace('V','v');
    
    ensureOperation(op, alg);
    
    var normAlg;
    switch (algName) {
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
          throw new NotSupportedError("Normalizing '" + algName 
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
          throw new NotSupportedError("Normalizing '" + algName 
                  + "' algorithm for op '" + op + "' not supported");
        }
        break;
      case 'PBKDF2':
        if(op === 'importKey') {
          normAlg = new Algorithm().init(alg);
        } else if(op === 'deriveBits') {
          normAlg = new Pbkdf2Params().init(alg);
        } else {
          throw new NotSupportedError("Normalizing '" + algName 
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
  return !!algorithmOperations[operation][algName];
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
  var operationFn = algorithmOperations[operation][normalizedAlgorithm.name];
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
        if(shouldFallBack('digest', err.name)) {
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
        resolve(key);
      }).catch(function(err) {
        if(shouldFallBack('generateKey', err.name)) {
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
      return toPromise(function() {return subtle.exportKey(format, key);});
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
    if(subtle) {
      toPromise(function() {
        return subtle.importKey(
                format, keyData, algorithm, extractable, usages);
      }).then(function(key) {
        resolve(key);
      }).catch(function(err) {
        if(shouldFallBack('importKey', err.name)) {
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
        // Here not try to convert key to native CryptoKey. The function
        // polyToNativeCryptoKey would call importKey to convert the key
        // to a native CryptoKey. But importKey would fail as before,
        // only because of that this function was called.
        resolve(key);
      }).catch(function(err) {
        reject(err);
      });
    }
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
        if(shouldFallBack('encrypt', err.name)) {
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
        if(shouldFallBack('decrypt', err.name)) {
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
          return subtle.wrapKey(
                  format, nativeKeys[0], nativeKeys[1], wrapAlgorithm);
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
        if(shouldFallBack('wrapKey', err.name)) {
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
          return subtle.unwrapKey(format, wrappedKey, nativeUnwrappingKey, 
                  unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, 
                  keyUsages);
        } else {
          return decrypt(unwrapAlgorithm, nativeUnwrappingKey, wrappedKey)
          .then(function(keyData) {
            if(format === 'jwk') {
              keyData = bytesToJwk(new Uint8Array(keyData));
            };
            if(!isJWK(keyData)) {
              throw new DataError('"wrappedKey" in no valid JWK');
            }
            return importKey(format, keyData, unwrappedKeyAlgorithm, 
                    extractable, keyUsages);
          });
        }
      }).then(function(unwrappedKey) {
        resolve(unwrappedKey);
      }).catch(function(err) {
        if(shouldFallBack('unwrapKey', err.name)) {
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
        return subtle.deriveKey(algorithm, nativeBaseKey, derivedKeyType, 
                extractable, keyUsages);
      }).then(function(key) {
        resolve(key);
      }).catch(function(err) {
        if(shouldFallBack('deriveKey', err.name)) {
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
      return subtle.deriveBits(algorithm, baseKey, length)
      .then(function(bits) {
        resolve(bits);
      }).catch(function(err) {
        if(shouldFallBack('deriveBits', err.name)) {
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