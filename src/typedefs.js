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