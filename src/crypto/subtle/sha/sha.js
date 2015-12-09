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