# Rust IdP Project

Identity Provider (IdP) の学習および LAN 内での検証利用を目的とした、シンプルな OAuth 2.0 / OpenID Connect (OIDC) 実装です。
コードの把握しやすさと OAuth 2.0 / OIDC 規格との互換性を重視し、役割ごとのクレート分割で構築しています。

## ワークスペース構成

* **`crypto`**: Argon2id によるパスワード・クライアントシークレットのハッシュ化・検証、PKCE (S256) チャレンジ生成。
* **`jwt_core`**: RS256 によるアクセストークン・IDトークン署名/検証と JWKS 生成。
* **`db_client`**: MySQL + SQLx (ランタイムクエリ + 自動マイグレーション) によるユーザー、クライアント、同意、リフレッシュトークンの永続化。
* **`oauth_flow`**: 認可コード・PKCE・リフレッシュトークンのデータモデルと検証ロジック。
* **`server`**: Axum ベースの IdP 本体（Port 3000）＋ React / TypeScript (Vite) フロントエンド（管理ポータルおよびログイン/同意画面、デジタル庁デザインシステムβ版準拠・ダークモード専用）。
* **`client_app`**: 検証用の外部アプリ役（Port 4000、Rust BFF + シンプルなバニラ HTML/JS）。

## 実装済みエンドポイント

### IdP (`server`)

* `GET /` — IdP 管理ポータル（クライアント一覧・登録、ユーザー登録、OIDC Discovery 確認）
* `GET /health` — ヘルスチェック
* `GET /.well-known/openid-configuration` — OIDC Discovery メタデータ
* `GET /.well-known/jwks.json` — RS256 公開鍵 (JWKS)
* `POST /register` — ユーザー登録 (`JSON`)
* `GET /authorize` — 認可エンドポイント (`response_type=code`, PKCE, `scope`, `state`, `nonce` → React ログイン/同意画面)
* `GET /api/auth/context` — 認可画面向けクライアント・スコープ情報取得
* `POST /login`, `POST /consent` — ログイン・同意処理（`JSON` API、セッション管理）
* `POST /token` — トークンエンドポイント (`application/x-www-form-urlencoded`, `client_secret_basic` / `client_secret_post`, `authorization_code` / `refresh_token`)
* `POST /revoke` — トークン失効 (`RFC 7009`, クライアント認証付き)
* `GET /userinfo` — UserInfo エンドポイント (`Bearer` JWT 検証、標準 `sub` クレーム返却)
* `GET, POST /api/admin/clients` — OAuth クライアント一覧取得・登録

### 検証用クライアント (`client_app`)

* `GET /login` / `GET /callback` — PKCE + `state` + `nonce` 付き認可コードフロー（トークンはサーバー側セッションに保持）
* `GET /api/session`, `GET /api/userinfo`, `GET /api/verify`, `POST /api/refresh`, `POST /api/logout`

## 開発環境のセットアップ

### 1. 鍵の生成と環境変数

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/private_key.pem -out keys/public_key.pem
cp example.env .env
```

### 2A. Docker Compose で一括起動（推奨）

`server` 起動時に `migrations/` が自動適用されます（マルチステージビルドにより最終イメージに Node.js や Rust ツールチェーンは含まれません）。

```bash
docker compose up -d --build
```

主な環境変数:
* `BIND_ADDR`: バインドアドレス（Docker 内では `0.0.0.0:3000` / `0.0.0.0:4000`）
* `IDP_BASE_URL`: ブラウザ向け IdP URL（認可画面リダイレクト・JWT `iss` 検証に使用）
* `IDP_INTERNAL_URL`: コンテナ間通信向け IdP URL（例: `http://server:3000`）
* `FRONTEND_DIR`: IdP フロントエンド (React ビルド済み `dist`) ディレクトリ
* `STATIC_DIR`: `client_app` の静的ファイルディレクトリ

### 2B. ローカル開発（ホットリロード）

```bash
# DB のみ Docker で起動
docker compose up -d db pma

# IdP サーバー起動 (Port 3000)
cd server/frontend && npm install && npm run build
cd ../.. && cargo run -p server

# 検証用クライアント起動 (Port 4000)
cargo run -p client_app

# IdP 管理ポータルの React 開発サーバーを使う場合 (Port 5173 -> 3000 へプロキシ)
cd server/frontend && npm run dev
```

### 3. 動作確認

1. ブラウザで `http://localhost:3000` を開き、IdP 管理ポータルからテスト用ユーザー（またはクライアント）を登録します（`curl` での `POST /register` も利用可能）。
2. ブラウザで `http://localhost:4000` を開き、ログイン・同意・UserInfo 取得・JWKS ローカル検証・リフレッシュ・ログアウトを確認します。
