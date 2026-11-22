# 1. IdP フロントエンド (React) ビルド
FROM node:22-slim AS frontend-builder
WORKDIR /frontend
COPY server/frontend/package.json server/frontend/package-lock.json ./
RUN npm ci
COPY server/frontend/ ./
RUN npm run build

# 2. Rust ワークスペースビルド
FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crypto ./crypto
COPY jwt_core ./jwt_core
COPY db_client ./db_client
COPY oauth_flow ./oauth_flow
COPY migrations ./migrations
COPY server/Cargo.toml ./server/Cargo.toml
COPY server/src ./server/src
COPY client_app/Cargo.toml ./client_app/Cargo.toml
COPY client_app/src ./client_app/src
RUN cargo build --release --bin server --bin client_app

# 3. IdP サーバー実行イメージ (Rust + React UI)
FROM debian:bookworm-slim AS server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=rust-builder /app/target/release/server /app/server
COPY --from=frontend-builder /frontend/dist /app/frontend
ENV BIND_ADDR=0.0.0.0:3000
ENV FRONTEND_DIR=/app/frontend
ENV PRIVATE_KEY_PATH=/app/keys/private_key.pem
ENV PUBLIC_KEY_PATH=/app/keys/public_key.pem
EXPOSE 3000
CMD ["/app/server"]

# 4. 検証用クライアントアプリ実行イメージ (Rust BFF + バニラ静的ファイル)
FROM debian:bookworm-slim AS client_app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=rust-builder /app/target/release/client_app /app/client_app
COPY client_app/static /app/static
ENV BIND_ADDR=0.0.0.0:4000
ENV STATIC_DIR=/app/static
EXPOSE 4000
CMD ["/app/client_app"]
