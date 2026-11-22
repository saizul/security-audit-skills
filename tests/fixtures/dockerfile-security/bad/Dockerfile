FROM node
ARG NPM_TOKEN
ARG GITHUB_TOKEN=not-a-real-token
ENV DB_PASSWORD=not-a-real-pass \
    NODE_ENV=production
ENV API_KEY ${API_KEY}
ADD https://example.com/tool.tar.gz /opt/
ADD config.json /app/config.json
COPY . /app
COPY .env /app/.env
RUN curl -fsSL https://example.com/install.sh | sh
RUN curl -k https://example.com/data -o /tmp/data && chmod -R 777 /app
RUN sudo apt-get update
EXPOSE 22 3000
USER root
CMD ["node", "server.js"]
