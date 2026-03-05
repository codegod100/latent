FROM oven/bun:latest

WORKDIR /app

# COPY from paths relative to build context (root)
COPY packages/server-docker/package.json packages/server-docker/bun.lock* ./
RUN bun install

COPY packages/shared/ ./src/shared/
COPY packages/server-docker/src/ ./src/
COPY packages/server-docker/server-config.toml ./

RUN mkdir -p /app/data

EXPOSE 8789

CMD ["bun", "run", "start"]
