FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy source
COPY src/ ./src/
COPY contracts/ ./contracts/

# Create non-root user
RUN addgroup -g 1001 -S credence && \
    adduser -S credence -u 1001
USER credence

# Expose port
EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8765/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

# Start gateway
CMD ["node", "src/index.js"]
