require('dotenv').config({ path: __dirname + '/config/.env.example' });
require('./config/db');

const express = require('express');
const cors = require('cors');
const http = require('http');
const useragent = require('express-useragent');
const expressip = require('express-ip');
const cookieParser = require('cookie-parser');
const logger = require('./middleware/logger');
const errorHandler = require('./middleware/error');
const { seedcoin } = require('./seeds/coins');


const app = express();
const port = process.env.PORT || 4320;
const socketPort = process.env.SOCKET_PORT || 4321;

// Middleware
app.use(express.json());
app.use(expressip().getIpInfoMiddleware);
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(logger)
app.use(useragent.express());

// CORS setup
app.use(cors({
    origin: [process.env.FRONTEND_USER_DOMAIN, process.env.FRONTEND_ADMIN_DOMAIN, process.env.LOCALHOST_DOMAIN, 'http://localhost:4201'],
    credentials: true,
    methods: ['POST', 'GET', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept'],
}));

// Routes

const userRouter = require('./routers/user');






const walletRouter = require('./routers/wallet');


app.use(userRouter);
app.use(walletRouter);





// Error handling middleware 
app.use(errorHandler);





seedcoin()


// WebSocket server
const sockserver = http.createServer(app);
sockserver.listen(socketPort, () => {
    console.log("Web Socket is running on http://localhost:%d", `${socketPort}`);
});


// Express server
const server = app.listen(port, () => {
    console.log(process.env.PLATFORM_NAME + " - Running on port: ", `${port}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error(`Unhandled Rejection: ${err.message}`);
    server.close(() => {
        process.exit(1);
    });
});

