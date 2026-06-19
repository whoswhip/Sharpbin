# syntax=docker/dockerfile:1
FROM node:20-alpine as build
ARG GIT_COMMIT_HASH
ENV GIT_COMMIT_HASH=${GIT_COMMIT_HASH}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine as runner
WORKDIR /app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=5173
COPY package.json package-lock.json ./
RUN apk add --no-cache wget libstdc++ \
    && apk add --no-cache --virtual .build-deps python3 make g++ \
    && npm ci --omit=dev \
    && npm cache clean --force \
    && apk del .build-deps
COPY --from=build --chown=node:node /app/build ./build
RUN chown -R node:node /app
EXPOSE 5173
USER node
CMD ["node", "build"]
