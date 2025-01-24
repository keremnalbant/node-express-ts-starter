import { version } from '../../package.json';
import { config } from '../config/config';

export const swaggerDefinition = {
  info: {
    license: {
      name: 'MIT',
      url: 'https://github.com/keremnalbant/node-express-ts-starter/blob/master/LICENSE',
    },
    title: 'Node Starter API documentation',
    version,
  },
  openapi: '3.0.0',
  servers: [
    {
      url: `http://localhost:${config.port}/v1`,
    },
  ],
};
