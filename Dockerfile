FROM --platform=linux/amd64 node:24-alpine AS builder
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
RUN cd node_modules/better-sqlite3 && npm run build-release
COPY src/ ./src/
COPY tsconfig.json ./
RUN npm run build

FROM --platform=linux/amd64 node:24-alpine AS production
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json ./
COPY --from=builder /app/dist ./dist
RUN npm ci --omit=dev --ignore-scripts && cd node_modules/better-sqlite3 && npm run build-release
RUN apk del python3 make g++ && npm cache clean --force
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
RUN mkdir -p /app/data
RUN chown -R nodejs:nodejs /app
USER nodejs
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + process.env.PORT + '/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "dist/server/http.js"]
