FROM node:20-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json webpack.config.js ./
COPY src ./src
RUN npm run build


FROM node:20-alpine

ARG VERSION
LABEL version="SMTP2Graph v${VERSION}"

COPY --from=builder /build/dist/server.js /bin/smtp2graph.js
COPY docker/startup.sh /bin/
COPY docker/test.sh /bin/

RUN chmod +x /bin/startup.sh /bin/test.sh

WORKDIR /data
VOLUME /data
EXPOSE 587
ENTRYPOINT ["startup.sh"]
