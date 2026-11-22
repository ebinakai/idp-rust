# idp-rust クライアント連携仕様（RP / 別プロジェクト向け）

このドキュメントは、別プロジェクト（Relying Party / OAuth 2.0 クライアント）から `idp-rust` と連携・検証するための実装仕様メモです。  
別の会話・別ワークスペースでクライアント側を実装・修正する際は、このファイルをそのまま参照させてください。

---

## 1. ベースURLと起動環境

- **デフォルトの IdP URL (`ISSUER`)**: `http://localhost:3000`
- **管理画面**: `http://localhost:3000/`（`is_admin = true` のユーザーでログインして OAuth クライアントを登録）
- **マイページ / ログイン画面**: `http://localhost:3000/account`
- **Docker コンテナからホスト上の `idp-rust` に接続する場合**:
  - ブラウザ向けリダイレクトURL (`authorize`) は `http://localhost:3000`
  - サーバー間バックチャネル通信 (`/token`, `/userinfo`, `/revoke`, `/.well-known/jwks.json`) は `http://host.docker.internal:3000`
  - ※ ID Token の `iss` クレーム検証を行う場合は、`idp-rust` 側の `ISSUER`（デフォルト `http://localhost:3000`）と一致させること。

---

## 2. クライアント登録

`http://localhost:3000/` の管理画面から OAuth クライアントを登録します。

- **`client_id`**: UUID 文字列（例: `550e8400-e29b-41d4-a716-446655440000`）。**整数 (`int`) ではないため、必ず文字列として扱うこと。**
- **`client_secret`**: Confidential Client の場合に発行される文字列（Public Client の場合はなし）。
- **`redirect_uris`**: 完全一致で検証される（例: `http://localhost:9999/auth/callback`）。

---

## 3. エンドポイント仕様

### Discovery / JWKS
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`（署名アルゴリズム: `RS256`）

### 認可エンドポイント: `GET /authorize`
ブラウザをリダイレクトする先。

クエリパラメータ:
- `response_type`: **`"code"` のみ対応**（必須）
- `client_id`: UUID 文字列（必須）
- `redirect_uri`: 登録済み URI と完全一致（必須）
- `scope`: 任意（OIDC の `id_token` を受け取る場合は `"openid"` を含める。例: `"openid profile"`）
- `state`: 任意（CSRF 対策のため推奨）
- `nonce`: 任意（`id_token` リプレイ対策）
- `code_challenge`: Public Client の場合は必須。Confidential Client でも推奨
- `code_challenge_method`: `"S256"` または `"plain"`（省略時 `"plain"`）

成功時、`redirect_uri?code=...&state=...` にリダイレクトされます。

### トークンエンドポイント: `POST /token`
`Content-Type: application/x-www-form-urlencoded` で送信します。

クライアント認証方式:
- `client_secret_basic`（`Authorization: Basic base64(client_id:client_secret)`）
- `client_secret_post`（フォームボディに `client_id` と `client_secret`）
- `none`（Public Client の場合、フォームボディに `client_id` のみ）

#### `grant_type=authorization_code`
- 必須パラメータ: `grant_type=authorization_code`, `code`, `redirect_uri`
- PKCE 使用時: `code_verifier`
- レスポンス例 (`200 OK`):
```json
{
  "access_token": "<JWT (RS256)>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "id_token": "<JWT (RS256), scope に openid を含む場合のみ>",
  "refresh_token": "<opaque token>"
}
```

#### `grant_type=refresh_token`
- 必須パラメータ: `grant_type=refresh_token`, `refresh_token`
- リフレッシュトークンは**ローテーション方式**（使用された旧 `refresh_token` は削除され、新しい `refresh_token` が返る）。

### UserInfo エンドポイント: `GET /userinfo`
ヘッダ: `Authorization: Bearer <access_token>`

レスポンス (`200 OK`):
```json
{
  "sub": "<user.id (UUID)>",
  "preferred_username": "<username>",
  "name": "<username>"
}
```

### トークン失効エンドポイント: `POST /revoke` (RFC 7009)
`Content-Type: application/x-www-form-urlencoded` + クライアント認証。
- パラメータ: `token`（リフレッシュトークン）
- 成功時: `200 OK`

---

## 4. 未実装機能・実装上の注意点（ハマりやすいポイント）

1. **RP-Initiated Logout（`/logout` や `/auth/logout`）は未実装**
   - ログアウト時はクライアント側のセッションを破棄し、必要に応じて `POST /revoke` で `refresh_token` を失効させてください。
2. **`/userinfo` に `email` や `role` は含まれない**
   - 返却されるクレームは `sub`, `preferred_username`, `name` のみです。クライアント側で `role` ベースの権限制御がある場合は、クライアント側 DB で `sub` に紐づけるなどの対応が必要です。
3. **`client_id` は UUID 文字列**
   - 数値としてパースするとエラーになります。
4. **パスは OAuth / OIDC 標準のルート直下**
   - `/auth/token` や `/auth/user_info` ではなく、**`/token`** と **`/userinfo`** です。
