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