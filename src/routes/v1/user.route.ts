import express from 'express';

import * as userController from '../../controllers/user.controller';
import { auth } from '../../middlewares/auth';
import { validate } from '../../middlewares/validate';
import * as userValidation from '../../validations/user.validation';

const router = express.Router();

router
  .route('/')
  .post(auth('manageUsers'), validate(userValidation.createUserSchema), userController.createUser)
  .get(auth('getUsers'), validate(userValidation.getUsersSchema), userController.getUsers);

router
  .route('/:userId')
  .get(auth('getUsers'), validate(userValidation.getUserSchema), userController.getUser)
  .patch(auth('manageUsers'), validate(userValidation.updateUserSchema), userController.updateUser)
  .delete(auth('manageUsers'), validate(userValidation.deleteUserSchema), userController.deleteUser);

export default router;
