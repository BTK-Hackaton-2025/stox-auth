# ───────── Stage 1 – build ─────────
FROM node:18-alpine AS builder

WORKDIR /app

# Install dependencies first (leverages Docker layer cache)
COPY package*.json ./
RUN npm ci

# Copy source and compile TypeScript -> JavaScript
COPY . .
RUN npm run build

# ───────── Stage 2 – runtime ─────────
FROM node:18-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV DOCKER_CONTAINER=true

# Copy only what we need to run the app
COPY --from=builder /app/dist        ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

# Expose HTTP (REST) and gRPC ports
EXPOSE 5051 50051

CMD ["node", "dist/src/main.js"]