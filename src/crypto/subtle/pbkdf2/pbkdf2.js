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