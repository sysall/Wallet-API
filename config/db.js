const mongoose = require('mongoose');
const options = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    connectTimeoutMS: 10000, // 10 seconds
    serverSelectionTimeoutMS: 10000 // 10 seconds
};
mongoose.set('strictQuery', false);

// Connect to the MongoDB database
mongoose.connect(process.env.MONGODB_URL, options);
// mongoose.connect(`${process.env.MONGODB_URL}?replicaSet=rs0&readPreference=primaryPreferred`, options);

mongoose.connection.on('connected', function () {
    console.log('Mongoose connection is open');
});

mongoose.connection.on('error', function (err) {
    console.error('Mongoose connection has occurred ' + err + ' error');
});

mongoose.connection.on('disconnected', function () {
    console.log('Mongoose connection is disconnected');
});

// Function to handle graceful termination
const gracefulExit = () => {
    mongoose.connection.close().then(() => {
        console.log("Mongoose default connection is disconnected due to application termination");
        process.exit(0);
    }).catch((error) => {
        console.error('Error while closing Mongoose connection:', error);
        process.exit(1);
    });
};

// Handle SIGINT (Ctrl+C) and SIGTERM signals
process.on('SIGINT', gracefulExit);
process.on('SIGTERM', gracefulExit);