!function() {
  if(!global.Promise && global.ES6Promise) {
    ES6Promise.polyfill();
  }
}();