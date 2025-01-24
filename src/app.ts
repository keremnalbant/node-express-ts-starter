import compression from 'compression';
import cors from 'cors';
import express from 'express';
import mongoSanitize from 'express-mongo-sanitize';
import session from 'express-session';
import helmet from 'helmet';
import httpStatus from 'http-status';
import passport from 'passport';
import xss from 'xss-clean';

import { config } from './config/config';
import morgan from './config/morgan';
import { jwtStrategy } from './config/passport';
import { errorConverter, errorHandler } from './middlewares/error';
import { authLimiter } from './middlewares/rateLimiter';
import routes from './routes/v1';
import { ApiError } from './utils/ApiError';

const app = express();

if (config.env !== 'test') {
  app.use(morgan.successHandler);
  app.use(morgan.errorHandler);
}

// set security HTTP headers
app.use(helmet());

// parse json request body
app.use(express.json());

// parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    resave: false,
    saveUninitialized: false,
    secret: config.jwt.secret,
  }),
);

// sanitize request data
app.use(xss());
app.use(mongoSanitize());

// gzip compression
app.use(compression());

// enable cors
app.use(
  cors({
    credentials: true,
    origin: 'http://localhost:5173',
  }),
);
app.options(
  '*',
  cors({
    credentials: true,
    origin: 'http://localhost:5173',
  }),
);

// jwt authentication
app.use(passport.initialize());
passport.use('jwt', jwtStrategy);

// limit repeated failed requests to auth endpoints
if (config.env === 'production') {
  app.use('/v1/auth', authLimiter);
}

// v1 api routes
app.use('/v1', routes);

// send back a 404 error for any unknown api request
app.use((req, res, next) => {
  next(new ApiError(httpStatus.NOT_FOUND, 'Not found'));
});

// convert error to ApiError, if needed
app.use(errorConverter);

// handle error
app.use(errorHandler);

export default app;
