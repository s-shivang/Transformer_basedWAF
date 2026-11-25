# Multi-stage Dockerfile for NestJS API Control Plane
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root & app manifests
COPY package.json package-lock.json* ./
COPY prisma ./prisma/

# Install dependencies including Prisma CLI
RUN npm ci

# Generate Prisma Client
RUN npx prisma generate

# Copy source and config
COPY tsconfig*.json nest-cli.json ./
COPY src ./src/

# Build NestJS distribution
RUN npm run build

# Production Runtime Stage
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install openssl for Prisma runtime
RUN apk add --no-cache openssl

COPY package.json package-lock.json* ./
COPY prisma ./prisma/

# Install production dependencies only
RUN npm ci --omit=dev && npx prisma generate

# Copy built artifacts from builder
COPY --from=builder /app/dist ./dist

EXPOSE 3000

# Entrypoint script: Push Prisma schema to Postgres on boot, then start NestJS
CMD ["sh", "-c", "npx prisma db push --skip-generate --accept-data-loss && node dist/main.js"]
