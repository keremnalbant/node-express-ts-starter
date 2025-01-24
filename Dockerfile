FROM node:hydrogen-alpine

RUN mkdir -p /usr/src/node-starter && chown -R node:node /usr/src/node-starter

WORKDIR /usr/src/node-starter

COPY package.json yarn.lock ./

USER node

RUN yarn install --pure-lockfile

COPY --chown=node:node . .

RUN yarn build

RUN yarn global add pm2

EXPOSE 3000

CMD ["yarn", "start"]
