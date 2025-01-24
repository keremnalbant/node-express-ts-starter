import express from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

import { swaggerDefinition } from '../../docs/swaggerDef';

const router = express.Router();

const specs = swaggerJsdoc({
  apis: ['src/docs/*.yml'],
  swaggerDefinition,
});

router.use('/', swaggerUi.serve);
router.get(
  '/',
  swaggerUi.setup(specs, {
    explorer: true,
  }),
);

export default router;
