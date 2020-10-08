var Joi = require('joi');

// Declare Api error class
const ApiError = function(req) {
    Error.call(this, 'An error occured on path: '+this.path);
    if(req) {
        this.path = req.path;
        this.req = req;
    }
};
ApiError.prototype = Object.create(Error.prototype);
ApiError.prototype.constructor = ApiError;

//method to check object validity according to given schema
ApiError.prototype.invalidate = function (obj, schema, next) {
    var e = Joi.validate(obj, schema);
    //if schema ins't valid throw a Validation error to the handler
    if(e && e.error) {
        this.e = e.error;
        this.message = this.e.name+": "+this.e.details.map(item => item.message).join(', ');
        next(this);
    }
    return  e && e.error !== null;
};

//method to generate not found error for requested object
ApiError.prototype.missingEntity = function (next) {
    this.message = "Entity not found";
    this.e = {
        name: "NotFoundError",
        details: []
    };
    //throw the Not Found error to the handler
    next(this);
};

//method to generate conflict error for requested object
ApiError.prototype.conflictedEntity = function (next) {
    this.message = "Entity already exist, target entity cannot be saved because another entity already contain unique fields with the same value.";
    this.e = {
        name: "ConflictError",
        details: []
    };
    //throw the Conflict error to the handler
    next(this);
};

//method to set custom error type and message
ApiError.prototype.setUpError = function (message, type, details) {
    this.message = message;
    this.e = {
        name: type,
        details: details
    }

};

//customise toString method for console display
ApiError.prototype.toString = function () {
    try {
        return JSON.stringify(this.toJSON(), 2);
    } catch (e) {
        return "Error: Error can't be displayed";
    }
};

//customize toJSON method to format response for the API
ApiError.prototype.toJSON = function () {
    return {
        path: this.path,
        message: this.message,
        type: this.e.name,
        details: this.e.details

    };
};


// Declare Auth error class
const AuthError = function(req) {
    Error.call(this, 'An error occured on path: '+this.path);
    if(req) {
        this.path = req.path;
    }
};
AuthError.prototype = Object.create(Error.prototype);
AuthError.prototype.constructor = AuthError;
//set up prototype methode to the same as Api errors for toJSON, toString and setUpError
AuthError.prototype.toJSON = ApiError.prototype.toJSON;
AuthError.prototype.toString = ApiError.prototype.toString;
AuthError.prototype.setUpError = ApiError.prototype.setUpError;

//handle authentications errors
var authHandleError = (error, req, res, next) => {

    //check error kind and handle Authentication errors
    if(error instanceof AuthError) {
        //log the error on debug
        _console.debug("AuthError - Stack: ", error);

        if(!currentConf.debug) {
            //remove the error stack if not on debug
            delete error.stack;
        }

        //set default response to code Bad Request
        let code = 400;
        let e = error.toJSON();
        //for Auth error, respond with 401 authentication error
        if(e.type === "AuthenticationError") {
            //set header for supported Authentication method
            res.setHeader("WWW-Authenticate", "Bearer");
            code = 401;
        }
        //for Access errors set 403 => forbidden
        if(e.type === "AccessError") {
            code = 403;
        }
        _console.warn("API :: Auth error - ", e.type, ": ", code,",", e.message);

        return res.status(code).json({
            error: "AuthError",
            message: error.message,
            statusCode: code,
            originalError: e
        });
    }

    next(error);
};

//handle API errors (=> validations errors)
var apiHandleError = (error, req, res, next) => {

    //check for Api error kind and handle them
    if(error instanceof ApiError) {
        //log the error on debug
        _console.debug("ApiError - Stack: ", error);

        if(!currentConf.debug) {
            //remove the error stack if not on debug
            delete error.stack;
        }
        //default error code to Bad request
        let code = 400;
        let e = error.toJSON();
        let type = "ApiError";

        //if error is of "not found" type change code to 404 > Not found
        if(e.type === 'NotFoundError') {
            code = 404;
            type = e.type;
        }

        //check for 'duplicates' kind of errors
        if(e.type === 'ConflictError') {
            //set custom code - 409 => Conflict error
            code = 409;
            type = e.type;
        }
        _console.warn("API :: Api error - ", e.type, ": ", code,",", e.message);

        return res.status(code).json({
            error: type,
            message: error.message,
            statusCode: code,
            originalError: e
        });
    }

    next(error);
};

//handle database errors
var databaseHandleError = (error, req, res, next) => {
    //check error type and handle database ones
    if(error instanceof DatabaseError) {
        //log the error on debug
        _console.debug("DatabaseError - Stack: ", error);

        if(!currentConf.debug) {
            //remove the error stack if not on debug
            delete error.stack;
        }
        //set default error code and message to database error message and 400 => Bad request error code
        let code = 400;
        let message = error.message;

        //check for 'duplicates' kind of errors
        if(error.name === DatabaseError.ERRORS_NAME && (error.code === DatabaseError.DATABASE_ERR_CODES.DUPLICATE_ENTRY || error.message.match(new RegExp('E'+DatabaseError.DATABASE_ERR_CODES.DUPLICATE_ENTRY, "ig")))) {
            //set custom message and code - 409 => Conflict error
            code = 409;
            message = "Entity already exist, target entity cannot be saved because another entity already contain unique fields with the same value.";
        }
        _console.error("API :: Database error : ", code,",", message);
        //throw database error
        return res.status(code).json({
            error: "DatabaseError",
            message: message,
            statusCode: code,
            originalError: error
        });
    }

    next(error);
};

//get any undefined error, execution errors are catched here
var anyHandleError = (error, req, res, next) => {

    //log the error on debug
    _console.debug("UnknownError - Stack: ", error);

    if(!currentConf.debug) {
        //remove the error stack if not on debug
        delete error.stack;
    }
    //throw a 500 error
    return res.status(500).json({
        error: "UnknownError",
        message: error.message,
        originalError: error
    });


};

//get unhandled errors which are happening on unhandled path
var defaultHandleError = (req, res) => {

    _console.debug('API :: path not found for this api');

    if(excludedPath && req.path.match(excludedPath)) return ;

    _console.warn("API :: path not found error - raw 404");
    //throw a 404 error for path
    return res.status(404).json({
        error: "NotFoundError",
        message: "path "+req.path+" is not found",
        statusCode: 404
    });
};

var Errors = {
    ApiError: ApiError,
    AuthError: AuthError
};
var DatabaseError;
var currentConf;
var excludedPath;
var _console;

module.exports = {
    setErrorHandler: (app, exclude, setLog) => {
        let db = require('actimage-mongodb-driver-tools');
        currentConf = app.get('cfg');
        currentConf.debug = currentConf.debug || process.env.DEBUG;

        if(setLog) {
            _console = console;
            //handle log level
            if(!process.env.DEBUG) {
                _console.debug = () => null;
            }
        } else {
            _console = {
                log: () => null,
                info: () => null,
                warn: () => null,
                debug: () => null,
                error: () => null
            }
        }



        //set up database error class for database errors handling
        Errors.DatabaseError = db.errorClass;
        DatabaseError = Errors.DatabaseError;
        excludedPath = exclude;
        //set various error handlers for the app
        app.use(authHandleError);
        app.use(apiHandleError);
        app.use(databaseHandleError);
        app.use(defaultHandleError);
        app.use(anyHandleError);

    },

    Errors: Errors,
    SocketErrors: require('./socket-error-handling')
};