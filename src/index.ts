import type { IncomingMessage, Server, ServerResponse } from 'http';

import mongoose from 'mongoose';

import app from './app';
import { config } from './config/config';
import logger from './config/logger';
import type { ApiError } from './utils/ApiError';

let server: Server<typeof IncomingMessage, typeof ServerResponse>;

mongoose
  .connect(config.mongoose.url)
  .then(() => {
    logger.info('Connected to MongoDB');
  })
  .catch((error) => {
    logger.error('Error connecting to MongoDB: ', error);
    process.exit(1);
  });

const exitHandler = () => {
  if (server) {
    server.close(() => {
      logger.info('Server closed');
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
};

const unexpectedErrorHandler = (error: ApiError) => {
  logger.error(error);
  exitHandler();
};

process.on('uncaughtException', unexpectedErrorHandler);
process.on('unhandledRejection', unexpectedErrorHandler);

process.on('SIGTERM', () => {
  logger.info('SIGTERM received');
  if (server) {
    server.close();
  }
});

server = app.listen(config.port, () => {
  logger.info(`Listening to port ${config.port}`);
});
