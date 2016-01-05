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
}


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
    jwk = JSON.parse(bytesToString(bytes, true));
  } catch(err) {
    throw new DataError('JWK could not be parsed. Invalid data format');
  }
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
  return (key instanceof exports.CryptoKey);
}
