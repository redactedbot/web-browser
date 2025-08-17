# Dockerfile
FROM ghcr.io/puppeteer/puppeteer:latest

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --production

COPY . .

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
