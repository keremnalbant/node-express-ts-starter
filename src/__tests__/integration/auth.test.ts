import { faker } from '@faker-js/faker';
import bcrypt from 'bcryptjs';
import httpStatus from 'http-status';
import moment from 'moment';
import { Types } from 'mongoose';
import httpMocks from 'node-mocks-http';
import request from 'supertest';

import app from '../../app';
import { config } from '../../config/config';
import { roleRights } from '../../config/roles';
import { TokenType } from '../../config/tokens';
import { auth } from '../../middlewares/auth';
import { User, Token, type IUser } from '../../models';
import * as emailService from '../../services/email.service';
import * as tokenService from '../../services/token.service';
import { ApiError } from '../../utils/ApiError';
import { userOneAccessToken, adminAccessToken } from '../fixtures/token.fixture';
import { userOne, admin, insertUsers } from '../fixtures/user.fixture';

describe('Auth routes', () => {
  describe('POST /v1/auth/register', () => {
    let newUser: Partial<IUser>;
    beforeEach(() => {
      newUser = {
        email: faker.internet.email().toLowerCase(),
        firstName: faker.person.firstName(),
        lastName: faker.person.lastName(),
        password: 'password1',
      };
    });

    test('should return 201 and successfully register user if request data is ok', async () => {
      const res = await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.CREATED);

      expect(res.body.user).not.toHaveProperty('password');
      expect(res.body.user).toEqual({
        id: expect.anything(),
        email: newUser.email,
        firstName: newUser.firstName,
        isEmailVerified: false,
        lastName: newUser.lastName,
        role: 'user',
      });

      const dbUser = await User.findById(res.body.user.id);
      expect(dbUser).toBeDefined();
      expect(dbUser.password).not.toBe(newUser.password);
      expect(dbUser).toMatchObject({
        email: newUser.email,
        firstName: newUser.firstName,
        isEmailVerified: false,
        lastName: newUser.lastName,
        role: 'user',
      });

      expect(res.body.tokens).toEqual({
        access: { expires: expect.anything(), token: expect.anything() },
        refresh: { expires: expect.anything(), token: expect.anything() },
      });
    });

    test('should return 400 error if email is invalid', async () => {
      newUser.email = 'invalidEmail';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if email is already used', async () => {
      await insertUsers([userOne]);
      newUser.email = userOne.email;

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password length is less than 8 characters', async () => {
      newUser.password = 'passwo1';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password does not contain both letters and numbers', async () => {
      newUser.password = 'password';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);

      newUser.password = '11111111';

      await request(app).post('/v1/auth/register').send(newUser).expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/login', () => {
    test('should return 200 and login user if email and password match', async () => {
      await insertUsers([userOne]);
      const loginCredentials = {
        email: userOne.email,
        password: userOne.password,
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.OK);

      expect(res.body.user).toEqual({
        id: expect.anything(),
        email: userOne.email,
        firstName: userOne.firstName,
        isEmailVerified: userOne.isEmailVerified,
        lastName: userOne.lastName,
        role: userOne.role,
      });

      expect(res.body.tokens).toEqual({
        access: { expires: expect.anything(), token: expect.anything() },
        refresh: { expires: expect.anything(), token: expect.anything() },
      });
    });

    test('should return 401 error if there are no users with that email', async () => {
      const loginCredentials = {
        email: userOne.email,
        password: userOne.password,
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({ code: httpStatus.UNAUTHORIZED, message: 'Incorrect email or password' });
    });

    test('should return 401 error if password is wrong', async () => {
      await insertUsers([userOne]);
      const loginCredentials = {
        email: userOne.email,
        password: 'wrongPassword1',
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({ code: httpStatus.UNAUTHORIZED, message: 'Incorrect email or password' });
    });
  });

  describe('POST /v1/auth/logout', () => {
    test('should return 204 if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
      await tokenService.saveToken({
        blacklisted: false,
        expires,
        token: refreshToken,
        type: TokenType.REFRESH,
        userId: userOne._id,
      });

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NO_CONTENT);

      const dbRefreshTokenDoc = await Token.findOne({ token: refreshToken });
      expect(dbRefreshTokenDoc).toBe(null);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/logout').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if refresh token is not found in the database', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NOT_FOUND);
    });

    test('should return 404 error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
      await tokenService.saveToken({
        blacklisted: true,
        expires,
        token: refreshToken,
        type: TokenType.REFRESH,
        userId: userOne._id,
      });

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/refresh-tokens', () => {
    test('should return 200 and new auth tokens if refresh token is valid', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
      await tokenService.saveToken({
        expires,
        token: refreshToken,
        type: TokenType.REFRESH,
        userId: userOne._id,
      });

      const res = await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.OK);

      expect(res.body).toEqual({
        access: { expires: expect.anything(), token: expect.anything() },
        refresh: { expires: expect.anything(), token: expect.anything() },
      });

      const dbRefreshTokenDoc = await Token.findOne({ token: res.body.refresh.token });
      expect(dbRefreshTokenDoc).toMatchObject({
        blacklisted: false,
        type: TokenType.REFRESH,
        user: new Types.ObjectId(userOne._id),
      });

      const dbRefreshTokenCount = await Token.countDocuments();
      expect(dbRefreshTokenCount).toBe(1);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/refresh-tokens').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 error if refresh token is signed using an invalid secret', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({
        expires,
        secret: 'invalidSecret',
        type: TokenType.REFRESH,
        userId: userOne._id,
      });
      await tokenService.saveToken({ expires, token: refreshToken, type: TokenType.REFRESH, userId: userOne._id });

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is not found in the database', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
      await tokenService.saveToken({
        blacklisted: true,
        expires,
        token: refreshToken,
        type: TokenType.REFRESH,
        userId: userOne._id,
      });

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is expired', async () => {
      await insertUsers([userOne]);
      const expires = moment().subtract(1, 'minutes');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
      await tokenService.saveToken({ expires, token: refreshToken, type: TokenType.REFRESH, userId: userOne._id });

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if user is not found', async () => {
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
      await tokenService.saveToken({ expires, token: refreshToken, type: TokenType.REFRESH, userId: userOne._id });

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/forgot-password', () => {
    beforeEach(() => {
      jest.spyOn(emailService.transport, 'sendMail').mockResolvedValue({
        accepted: [userOne.email],
        envelope: { from: 'random@random.com', to: [userOne.email] },
        messageId: 'randomString',
        pending: [''],
        rejected: [''],
        response: 'Success',
      });
    });

    test('should return 204 and send reset password email to the user', async () => {
      await insertUsers([userOne]);
      const sendResetPasswordEmailSpy = jest.spyOn(emailService, 'sendResetPasswordEmail');

      await request(app).post('/v1/auth/forgot-password').send({ email: userOne.email }).expect(httpStatus.NO_CONTENT);

      // to have been called with object {to: "userOne.email", token: "expect.any(String)"}
      expect(sendResetPasswordEmailSpy).toHaveBeenCalledWith(
        expect.objectContaining({ to: userOne.email, token: expect.any(String) }),
      );

      const resetPasswordToken = sendResetPasswordEmailSpy.mock.calls[0][0].token;
      const dbResetPasswordTokenDoc = await Token.findOne({ token: resetPasswordToken, user: userOne._id });
      expect(dbResetPasswordTokenDoc).toBeDefined();

      expect(emailService.transport.sendMail).not.toThrow();
    });

    test('should return 400 if email is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/forgot-password').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 if email does not belong to any user', async () => {
      await request(app).post('/v1/auth/forgot-password').send({ email: userOne.email }).expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/reset-password', () => {
    test('should return 204 and reset the password', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken({
        expires,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });
      await tokenService.saveToken({
        expires,
        token: resetPasswordToken,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.NO_CONTENT);

      const dbUser = await User.findById(userOne._id);
      const isPasswordMatch = await bcrypt.compare('password2', dbUser.password);
      expect(isPasswordMatch).toBe(true);

      const dbResetPasswordTokenCount = await Token.countDocuments({ type: TokenType.RESET_PASSWORD, user: userOne._id });
      expect(dbResetPasswordTokenCount).toBe(0);
    });

    test('should return 400 if reset password token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/reset-password').send({ password: 'password2' }).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if reset password token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken({
        expires,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });
      await tokenService.saveToken({
        blacklisted: true,
        expires,
        token: resetPasswordToken,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if reset password token is expired', async () => {
      await insertUsers([userOne]);
      const expires = moment().subtract(1, 'minutes');
      const resetPasswordToken = tokenService.generateToken({
        expires,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });
      await tokenService.saveToken({
        expires,
        token: resetPasswordToken,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if user is not found', async () => {
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken({
        expires,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });
      await tokenService.saveToken({
        expires,
        token: resetPasswordToken,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 if password is missing or invalid', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken({
        expires,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });
      await tokenService.saveToken({
        expires,
        token: resetPasswordToken,
        type: TokenType.RESET_PASSWORD,
        userId: userOne._id,
      });

      await request(app).post('/v1/auth/reset-password').query({ token: resetPasswordToken }).expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'short1' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: '11111111' })
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/send-verification-email', () => {
    beforeEach(() => {
      jest.spyOn(emailService.transport, 'sendMail').mockResolvedValue({
        accepted: [userOne.email],
        envelope: { from: 'random@random.com', to: [userOne.email] },
        messageId: 'randomString',
        pending: [''],
        rejected: [''],
        response: 'Success',
      });
    });

    test('should return 204 and send verification email to the user', async () => {
      await insertUsers([userOne]);
      const sendVerificationEmailSpy = jest.spyOn(emailService, 'sendVerificationEmail');

      await request(app)
        .post('/v1/auth/send-verification-email')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .expect(httpStatus.NO_CONTENT);

      expect(sendVerificationEmailSpy).toHaveBeenCalledWith(
        expect.objectContaining({ to: userOne.email, token: expect.any(String) }),
      );
      const verifyEmailToken = sendVerificationEmailSpy.mock.calls[0][0].token;
      const dbVerifyEmailToken = await Token.findOne({ token: verifyEmailToken, user: userOne._id });

      expect(dbVerifyEmailToken).toBeDefined();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/send-verification-email').send().expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/verify-email', () => {
    test('should return 204 and verify the email', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken({ expires, type: TokenType.VERIFY_EMAIL, userId: userOne._id });
      await tokenService.saveToken({ expires, token: verifyEmailToken, type: TokenType.VERIFY_EMAIL, userId: userOne._id });

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbUser = await User.findById(userOne._id);

      expect(dbUser.isEmailVerified).toBe(true);

      const dbVerifyEmailToken = await Token.countDocuments({
        type: TokenType.VERIFY_EMAIL,
        user: userOne._id,
      });
      expect(dbVerifyEmailToken).toBe(0);
    });

    test('should return 400 if verify email token is missing', async () => {
      await insertUsers([userOne]);

      await request(app).post('/v1/auth/verify-email').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if verify email token is blacklisted', async () => {
      await insertUsers([userOne]);
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken({ expires, type: TokenType.VERIFY_EMAIL, userId: userOne._id });
      await tokenService.saveToken({
        blacklisted: true,
        expires,
        token: verifyEmailToken,
        type: TokenType.VERIFY_EMAIL,
        userId: userOne._id,
      });

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if verify email token is expired', async () => {
      await insertUsers([userOne]);
      const expires = moment().subtract(1, 'minutes');
      const verifyEmailToken = tokenService.generateToken({ expires, type: TokenType.VERIFY_EMAIL, userId: userOne._id });
      await tokenService.saveToken({ expires, token: verifyEmailToken, type: TokenType.VERIFY_EMAIL, userId: userOne._id });

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if user is not found', async () => {
      const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
      const verifyEmailToken = tokenService.generateToken({ expires, type: TokenType.VERIFY_EMAIL, userId: userOne._id });
      await tokenService.saveToken({ expires, token: verifyEmailToken, type: TokenType.VERIFY_EMAIL, userId: userOne._id });

      await request(app)
        .post('/v1/auth/verify-email')
        .query({ token: verifyEmailToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });
  });
});

describe('Auth middleware', () => {
  test('should call next with no errors if access token is valid', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${userOneAccessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
    expect(req.user.id).toEqual(userOne._id);
  });

  test('should call next with unauthorized error if access token is not found in header', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest();
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Please authenticate', statusCode: httpStatus.UNAUTHORIZED }),
    );
  });

  test('should call next with unauthorized error if access token is not a valid jwt token', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: 'Bearer randomToken' } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Please authenticate', statusCode: httpStatus.UNAUTHORIZED }),
    );
  });

  test('should call next with unauthorized error if the token is not an access token', async () => {
    await insertUsers([userOne]);
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const refreshToken = tokenService.generateToken({ expires, type: TokenType.REFRESH, userId: userOne._id });
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${refreshToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Please authenticate', statusCode: httpStatus.UNAUTHORIZED }),
    );
  });

  test('should call next with unauthorized error if access token is generated with an invalid secret', async () => {
    await insertUsers([userOne]);
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const accessToken = tokenService.generateToken({
      expires,
      secret: 'invalidSecret',
      type: TokenType.ACCESS,
      userId: userOne._id,
    });
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Please authenticate', statusCode: httpStatus.UNAUTHORIZED }),
    );
  });

  test('should call next with unauthorized error if access token is expired', async () => {
    await insertUsers([userOne]);
    const expires = moment().subtract(1, 'minutes');
    const accessToken = tokenService.generateToken({ expires, type: TokenType.ACCESS, userId: userOne._id });
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Please authenticate', statusCode: httpStatus.UNAUTHORIZED }),
    );
  });

  test('should call next with unauthorized error if user is not found', async () => {
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${userOneAccessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Please authenticate', statusCode: httpStatus.UNAUTHORIZED }),
    );
  });

  test('should call next with forbidden error if user does not have required rights and userId is not in params', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${userOneAccessToken}` } });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ message: 'Forbidden', statusCode: httpStatus.FORBIDDEN }));
  });

  test('should call next with no errors if user does not have required rights but userId is in params', async () => {
    await insertUsers([userOne]);
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${userOneAccessToken}` },
      params: { userId: userOne._id },
    });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });

  test('should call next with no errors if user has required rights', async () => {
    await insertUsers([admin]);
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${adminAccessToken}` },
      params: { userId: userOne._id },
    });
    const next = jest.fn();

    await auth(...roleRights.get('admin'))(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });
});
