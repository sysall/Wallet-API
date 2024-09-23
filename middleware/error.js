const ErrorResponse = require('../utils/errorResponse');

const errorHandler = (err, req, res, next) => {
    // console.log("errorhandler user service")
    let error = { ...err };
    error.message = err.message;

    // console.log("err***",err)
    // Log to console for dev
    console.log(err);

    // Mongoose bad ObjectId
    if (err.name === 'CastError') {
        const message = `user not found with id of ${err.value}`;
        error = new ErrorResponse(message, 404);
    }

    // Mongoose duplicate key
    if (err.code === 11000 && err.name == 'MongoError') {
        if (error && error.keyValue && error.keyValue.email != null) {
            const message = "Email Id Is Already Registered"
            error = new ErrorResponse(message, 400)
        } else if (error && error.keyValue && error.keyValue.name != null) {
            const message = "Username Already Exist"
            error = new ErrorResponse(message, 400)
        } else {
            const message = 'Duplicate Entry is Restricted';
            // const message = 'Username/Mail Id Has Already Registered';
            error = new ErrorResponse(message, 400)
        }
    }

    // Mongoose validation error
    if (err.name === 'ValidationError') {
        const message = Object.values(err.errors).map(val => val.message);
        error = new ErrorResponse(message, 400)
    }

    res.status(error.statusCode || 500).json({
        success: false,
        message: error.message || 'Server Error'
    });
};

module.exports = errorHandler;