ARG NODE_IMAGE=node:26-slim
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:stable-alpine
USER root
RUN apk add --no-cache ca-certificates gettext
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html
COPY --chown=101:101 docker/nginx.conf.template /etc/cybertriage/nginx.conf.template
COPY --chmod=755 docker/start.sh /start.sh
RUN sed -i 's/\r$//' /start.sh
USER 101:101
EXPOSE 8080
ENTRYPOINT ["/start.sh"]
