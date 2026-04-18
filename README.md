# Rust IdP Project

---

## 概要

本プロジェクトは、Identity Provider (IdP) の複雑な認証フローやシステム要件のドメイン知識の学習及び、Rustによる実装を行うプロジェクトである。
巨大なシステムを一括で構築するのではなく、構成要素を極小の独立したモジュールとして一つずつ作成し、最終的に統合する「ボトムアップ開発」を採用している。

---

## 開発ロードマップとモジュール構成

本リポジトリはCargoワークスペースを用いて以下のモジュール群を一元管理する。

### 1. 独立したコアモジュール

* **`crypto`** (Done)
  * パスワードのハッシュ化および検証（Argon2）。
* **`jwt_core`** (Done)
  * JWTの発行と署名検証。
  * **Update**: 共通鍵（HS256）から非対称暗号（RS256）へ移行。公開鍵を外部へ安全に提供するためのJWKS（JSON Web Key Set）生成機能を実装済み。

### 2. 外部依存・プロトコル処理モジュール

* **`db_client`** (Done)
  * PostgreSQLへの非同期接続とCRUD操作の抽象化。
* **`oauth_flow`** (Done)
  * OAuth 2.0仕様に基づく認可コードのライフサイクル管理。メモリ安全なHashMapによる状態管理と、一回性（リプレイ攻撃防止）の保証。
* **`webauthn`** (Planned)
  * Passkey認証の実装。

### 3. 統合・サーバー層（フェーズ・トラッキング）

* **Phase 1: OAuth 2.0 基礎** (Done)
  * 認可コードフローによるアクセストークン発行。
* **Phase 2: OIDC (OpenID Connect) 対応** (Done)
  * `openid` スコープに基づく IDトークンの発行。
* **Phase 3: セキュリティ強化 (RS256/JWKS)** (Done)
  * 非対称暗号による署名と、`/.well-known/jwks.json` による鍵配布。
* **Phase 4: トークン・マネジメント** (In Progress)
  * リフレッシュトークンの導入と有効期限管理の厳格化。

---

## セキュリティ・鍵管理

本システムはRS256署名を採用している。開発用鍵の生成と取り扱いは以下の通りとする。

1. **秘密鍵の秘匿**: `private_key.pem` は絶対にリポジトリに含めない（`.gitignore` で除外）。
2. **公開鍵の配布**: 公開鍵は JWKS エンドポイントを通じて動的に配布され、クライアントはこれを自動取得して検証を行う。


```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/private_key.pem -out keys/public_key.pem
```

---

## 開発環境のセットアップ

```bash
# docker でDBを起動
docker compose up -d
sqlx migrate run

# IdPサーバーの起動 (Port 3000)
cd server && cargo run

# クライアントアプリの起動 (Port 4000)
cd client_app && cargo run
```
