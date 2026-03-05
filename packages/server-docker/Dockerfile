FROM oven/bun:latest

WORKDIR /app

# Preserve directory structure so relative imports work
COPY packages/shared/ ./packages/shared/
COPY packages/server-docker/ ./packages/server-docker/

WORKDIR /app/packages/server-docker
RUN bun install

RUN mkdir -p /app/data

EXPOSE 8789

CMD ["bun", "run", "start"]
