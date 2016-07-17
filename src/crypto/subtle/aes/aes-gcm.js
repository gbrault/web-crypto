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