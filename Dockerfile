# GeniSpace platform-internal operators (HTTP API + /static/plugins chat assets)
FROM node:20-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
RUN npm run build:all
ENV NODE_ENV=production
EXPOSE 8080
USER node
CMD ["node", "src/index.js"]
