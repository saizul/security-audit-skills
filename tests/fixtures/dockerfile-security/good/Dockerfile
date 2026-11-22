# syntax=docker/dockerfile:1
FROM node:22.11.0-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN="$(cat /run/secrets/npm_token)" npm ci
COPY . .
RUN npm run build

FROM node:22.11.0-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /src/dist ./dist
COPY --from=build /src/node_modules ./node_modules
USER node
EXPOSE 3000
HEALTHCHECK CMD node dist/healthcheck.js
CMD ["node", "dist/server.js"]
