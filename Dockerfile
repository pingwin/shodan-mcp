# Build stage for Shodan MCP server
FROM node:20-alpine AS shodan-builder

WORKDIR /app

# Copy package files and install all dependencies (need dev deps for build)
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

# Copy source and build
COPY src/ ./src/
RUN npm run build

# Reinstall only production dependencies
RUN rm -rf node_modules && npm ci --omit=dev

# Final stage - based on open-webui/mcpo
FROM ghcr.io/open-webui/mcpo:main

WORKDIR /app

# Copy built shodan server from builder
COPY --from=shodan-builder /app/dist ./dist
COPY --from=shodan-builder /app/node_modules ./node_modules

# Install additional dependencies needed by mcpo base
RUN npm install -g @modelcontextprotocol/sdk

# Expose the MCP port
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8000/health || exit 1
