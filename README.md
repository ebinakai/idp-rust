# Rust IdP Project

Identity Provider (IdP) の学習および LAN 内での検証利用を目的とした、シンプルな OAuth 2.0 / OpenID Connect (OIDC) 実装です。
コードの把握しやすさと OAuth 2.0 / OIDC 規格との互換性を重視し、役割ごとのクレート分割で構築しています。

## ワークスペース構成

* **`crypto`**: Argon2id によるパスワード・クライアントシークレットのハッシュ化・検証、PKCE (S256) チャレンジ生成。
* **`jwt_core`**: RS256 によるアクセストークン・IDトークン署名/検証と JWKS 生成。
* **`db_client`**: MySQL + SQLx (ランタイムクエリ) によるユーザー、クライアント、同意、リフレッシュトークンの永続化。
* **`oauth_flow`**: 認可コード・PKCE・リフレッシュトークンのデータモデルと検証ロジック。
* **`server`**: Axum ベースの IdP サーバー（Port 3000）。
* **`client_app`**: セッションベースの BFF 検証用クライアントアプリ（Port 4000）。

## 実装済みエンドポイント

### IdP (`server`)

* `GET /.well-known/openid-configuration` — OIDC Discovery メタデータ
* `GET /.well-known/jwks.json` — RS256 公開鍵 (JWKS)
* `POST /register` — ユーザー登録 (`JSON`)
* `GET /authorize` — 認可エンドポイント (`response_type=code`, PKCE, `scope`, `state`, `nonce`)
* `POST /login`, `POST /consent` — ログイン・同意画面（セッション管理）
* `POST /token` — トークンエンドポイント (`application/x-www-form-urlencoded`, `client_secret_basic` / `client_secret_post`, `authorization_code` / `refresh_token`)
* `POST /revoke` — トークン失効 (`RFC 7009`, クライアント認証付き)
* `GET /userinfo` — UserInfo エンドポイント (`Bearer` JWT 検証、標準 `sub` クレーム返却)
* `GET, POST /api/admin/clients` — OAuth クライアント一覧取得・登録

### 検証用クライアント (`client_app`)

* `GET /login` / `GET /callback` — PKCE + `state` + `nonce` 付き認可コードフロー（トークンはサーバー側セッションに保持）
* `GET /api/session`, `GET /api/userinfo`, `GET /api/verify`, `POST /api/refresh`, `POST /api/logout`

## 今後の予定（LAN 用途向け）

* 管理画面 UI (`server/templates/admin/index.html`) と管理 API の認証保護
* `server` / `client_app` のエンドポイント統合テストの拡充
* 外部 OIDC クライアントとの相互接続検証

## 開発環境のセットアップ

### 1. 鍵の生成

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/private_key.pem -out keys/public_key.pem
```

### 2. DB 起動とマイグレーション

```bash
cp example.env .env
docker compose up -d
sqlx migrate run
```

### 3. サーバー起動

```bash
# IdP サーバー (Port 3000)
cargo run -p server

# クライアントアプリ (Port 4000)
cargo run -p client_app
```
