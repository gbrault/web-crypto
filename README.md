# web-crypto
Web Cryptography API wrapper with asmCrypto fallback.

## Installation
web-crypto is available as bower package.
```
bower install web-crypto
```

Or you can download the [latest release](https://github.com/ssmtlbn/web-crypto/releases/latest) from the [releases page](https://github.com/ssmtlbn/web-crypto/releases) and copy the files from `dist` folder to your project.

## Dependencies
To use web-crypto, the browser has to support promises. You also have to include [asmCrypto](https://github.com/vibornoff/asmcrypto.js/) in your project, which you can find [here](https://github.com/vibornoff/asmcrypto.js/) (or you can use the included Grunt task **buildAsmCrypto** to build your own version of asmCrypto).

## Getting started
web-crypto can be used as stand-alone library or as [RequireJS](http://requirejs.org/) module.

##### Standalone
To load it as stand-alone library just include the script into your page. web-crypto is then available as global object `webCrypto`.
``` html
<script src="path/to/web-crypto/web-crypto.min.js"></script>
```
##### RequireJS
To use thread-woker with RequireJS, simply fetch the module.
```javascript
var webCrypto = require('web-crypto');
```
## Usage
For a full list of available objects and functions, see the [API](http://ssmtlbn.github.io/web-crypto/).