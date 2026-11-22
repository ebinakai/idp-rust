import { type FormEvent, useCallback, useEffect, useState } from "react";
import { AccountPage } from "./AccountPage";
import { AuthorizePage } from "./AuthorizePage";
import {
  accountLogout,
  createClient,
  fetchMe,
  fetchOpenIdConfig,
  listClients,
  type MeRes,
  type OAuthClientItem,
  type OpenIdConfig,
  registerUser,
} from "./api";

interface NoticeState {
  kind: "info" | "success" | "error";
  title: string;
  body: string;
}

export function App() {
  if (window.location.pathname === "/authorize") {
    return <AuthorizePage />;
  }
  if (window.location.pathname === "/account") {
    return <AccountPage />;
  }

  return <AdminPortal />;
}

function AdminPortal() {
  const [loading, setLoading] = useState(true);
  const [me, setMe] = useState<MeRes | null>(null);
  const [clients, setClients] = useState<OAuthClientItem[]>([]);
  const [discovery, setDiscovery] = useState<OpenIdConfig | null>(null);
  const [createdClient, setCreatedClient] = useState<OAuthClientItem | null>(null);
  const [notice, setNotice] = useState<NoticeState | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  // Initial setup form
  const [setupUsername, setSetupUsername] = useState("");
  const [setupPassword, setSetupPassword] = useState("");

  // Client creation form
  const [clientName, setClientName] = useState("");
  const [redirectUrisText, setRedirectUrisText] = useState("http://localhost:4000/callback");
  const [isConfidential, setIsConfidential] = useState(true);

  // User registration form
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [grantAdmin, setGrantAdmin] = useState(false);

  const reloadPortal = useCallback(async () => {
    const [meRes, configRes] = await Promise.all([fetchMe(), fetchOpenIdConfig()]);
    setMe(meRes);
    setDiscovery(configRes);

    if (meRes.logged_in && meRes.user?.is_admin) {
      const clientList = await listClients();
      setClients(clientList);
    } else {
      setClients([]);
    }
  }, []);

  useEffect(() => {
    reloadPortal()
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : "初期データの読み込みに失敗しました";
        setNotice({ kind: "error", title: "サーバー通信エラー", body: message });
      })
      .finally(() => setLoading(false));
  }, [reloadPortal]);

  async function copyText(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setNotice({
        kind: "info",
        title: "コピー完了",
        body: `${label} をクリップボードにコピーしました。`,
      });
    } catch {
      setNotice({
        kind: "error",
        title: "コピー失敗",
        body: "クリップボードへのアクセスが許可されませんでした。",
      });
    }
  }

  async function handleInitialSetup(e: FormEvent) {
    e.preventDefault();
    if (busyAction) return;

    if (!setupUsername.trim() || !setupPassword) {
      setNotice({
        kind: "error",
        title: "入力エラー",
        body: "ユーザー名とパスワードを入力してください。",
      });
      return;
    }

    setBusyAction("initial_setup");
    setNotice(null);
    try {
      await registerUser(setupUsername.trim(), setupPassword, true);
      await reloadPortal();
      setNotice({
        kind: "success",
        title: "初期管理者アカウントを作成しました",
        body: `管理者「${setupUsername.trim()}」としてログインしました。`,
      });
      setSetupUsername("");
      setSetupPassword("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "初期管理者の作成に失敗しました";
      setNotice({ kind: "error", title: "セットアップエラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleLogout() {
    if (busyAction) return;
    setBusyAction("logout");
    setNotice(null);
    try {
      await accountLogout();
      await reloadPortal();
      setCreatedClient(null);
      setNotice({
        kind: "info",
        title: "ログアウトしました",
        body: "管理セッションを終了しました。",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "ログアウトに失敗しました";
      setNotice({ kind: "error", title: "ログアウトエラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleCreateClient(e: FormEvent) {
    e.preventDefault();
    if (busyAction) return;

    const uris = redirectUrisText
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (!clientName.trim()) {
      setNotice({ kind: "error", title: "入力エラー", body: "クライアント名を入力してください。" });
      return;
    }
    if (uris.length === 0) {
      setNotice({
        kind: "error",
        title: "入力エラー",
        body: "1つ以上のリダイレクト URI を入力してください。",
      });
      return;
    }

    setBusyAction("create_client");
    setNotice(null);
    try {
      const created = await createClient({
        name: clientName.trim(),
        redirect_uris: uris,
        is_confidential: isConfidential,
      });
      setCreatedClient(created);
      setClients((prev) => [created, ...prev]);
      setClientName("");
      setNotice({
        kind: "success",
        title: "OAuth クライアントを登録しました",
        body: `クライアント「${created.name}」を作成しました。`,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "クライアントの登録に失敗しました";
      setNotice({ kind: "error", title: "クライアント登録エラー", body: message });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRegisterUser(e: FormEvent) {
    e.preventDefault();
    if (busyAction) return;

    if (!username.trim() || !password) {
      setNotice({
        kind: "error",
        title: "入力エラー",
        body: "ユーザー名とパスワードを入力してください。",
      });
      return;
    }

    setBusyAction("register_user");
    setNotice(null);
    try {
      await registerUser(username.trim(), password, grantAdmin);
      setNotice({
        kind: "success",
        title: "ユーザーを登録しました",
        body: `ユーザー「${username.trim()}」を作成しました。外部クライアントやマイページからログインできます。`,
      });
      setUsername("");
      setPassword("");
      setGrantAdmin(false);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "ユーザー登録に失敗しました";
      setNotice({ kind: "error", title: "ユーザー登録エラー", body: message });
    } finally {
      setBusyAction(null);
    }
  }

  const adminUser = me?.logged_in && me.user?.is_admin ? me.user : undefined;
  const isAdmin = Boolean(adminUser);

  return (
    <div className="dads-page">
      <header className="dads-header">
        <div className="dads-header__inner">
          <div className="dads-header__brand">
            <h1 className="dads-header__title">Rust IdP 管理ポータル</h1>
            {adminUser ? (
              <span className="dads-chip dads-chip--success">管理者: {adminUser.username}</span>
            ) : (
              <span
                className={`dads-chip ${discovery ? "dads-chip--success" : "dads-chip--error"}`}
              >
                {loading ? "接続確認中" : discovery ? "IdP 稼働中" : "接続エラー"}
              </span>
            )}
          </div>
          <div className="dads-header__actions">
            <a href="/account" className="dads-btn dads-btn--secondary dads-btn--sm">
              マイページ
            </a>
            {adminUser && (
              <button
                type="button"
                className="dads-btn dads-btn--secondary dads-btn--sm"
                onClick={handleLogout}
                aria-busy={busyAction === "logout"}
              >
                ログアウト
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="dads-main">
        {notice && (
          <div
            className={`dads-notice dads-notice--${notice.kind}`}
            role="status"
            aria-live="polite"
          >
            <p className="dads-notice__title">{notice.title}</p>
            <p className="dads-notice__body">{notice.body}</p>
          </div>
        )}

        {loading ? (
          <section className="dads-card" aria-busy="true">
            <div className="dads-card__main">
              <p className="dads-lead">ポータル状態を確認しています...</p>
            </div>
          </section>
        ) : me?.needs_setup ? (
          <section className="dads-card">
            <div className="dads-card__main">
              <h2 className="dads-heading-2">初期管理者アカウントの作成</h2>
              <p className="dads-lead">
                まだユーザーが登録されていません。最初に登録するアカウントが IdP
                の管理者になります。
              </p>

              <form className="dads-form" onSubmit={handleInitialSetup}>
                <div className="dads-field">
                  <label className="dads-label" htmlFor="setup-username">
                    管理者ユーザー名<span className="dads-req">※必須</span>
                  </label>
                  <input
                    id="setup-username"
                    type="text"
                    className="dads-input"
                    autoComplete="username"
                    value={setupUsername}
                    onChange={(e) => setSetupUsername(e.target.value)}
                  />
                </div>

                <div className="dads-field">
                  <label className="dads-label" htmlFor="setup-password">
                    パスワード<span className="dads-req">※必須</span>
                  </label>
                  <input
                    id="setup-password"
                    type="password"
                    className="dads-input"
                    autoComplete="new-password"
                    value={setupPassword}
                    onChange={(e) => setSetupPassword(e.target.value)}
                  />
                </div>

                <div className="dads-btn-group">
                  <button
                    type="submit"
                    className="dads-btn dads-btn--primary"
                    aria-busy={busyAction === "initial_setup"}
                  >
                    {busyAction === "initial_setup" ? "作成中..." : "初期管理者を作成して開始"}
                  </button>
                </div>
              </form>
            </div>
          </section>
        ) : !me?.logged_in ? (
          <section className="dads-card">
            <div className="dads-card__main">
              <h2 className="dads-heading-2">管理者ログインが必要です</h2>
              <p className="dads-lead">
                クライアント管理やユーザー作成を行うには、管理者アカウントでログインしてください（パスキーまたはパスワードでログインできます）。
              </p>
              <div className="dads-btn-group">
                <a href="/account" className="dads-btn dads-btn--primary">
                  ログイン（マイページ）へ
                </a>
              </div>
            </div>
          </section>
        ) : !isAdmin ? (
          <section className="dads-notice dads-notice--error">
            <p className="dads-notice__title">アクセス権限がありません</p>
            <p className="dads-notice__body" style={{ marginBottom: 16 }}>
              ログイン中のユーザー「{me.user?.username}
              」には管理者権限がありません。既存ユーザーを管理者にする場合は、サーバー環境変数{" "}
              <code>ADMIN_USERNAME={me.user?.username}</code> を設定して再起動してください。
            </p>
            <div className="dads-btn-group">
              <a href="/account" className="dads-btn dads-btn--secondary">
                マイページへ戻る
              </a>
            </div>
          </section>
        ) : (
          <>
            {createdClient && (
              <section className="dads-notice dads-notice--info" aria-live="polite">
                <p className="dads-notice__title">新規発行されたクライアント認証情報</p>
                <p className="dads-subtext" style={{ marginBottom: 12 }}>
                  client_secret はこの画面でのみ表示されます。必要に応じて控えてください。
                </p>
                <dl className="dads-dl">
                  <dt>client_id</dt>
                  <dd className="dads-inline-copy">
                    <span className="dads-mono">{createdClient.id}</span>
                    <button
                      type="button"
                      className="dads-btn dads-btn--secondary dads-btn--sm"
                      onClick={() => copyText(createdClient.id, "client_id")}
                    >
                      コピー
                    </button>
                  </dd>
                  <dt>client_secret</dt>
                  <dd className="dads-inline-copy">
                    <span className="dads-mono">
                      {createdClient.client_secret ?? "なし（パブリッククライアント / PKCE 必須）"}
                    </span>
                    {createdClient.client_secret && (
                      <button
                        type="button"
                        className="dads-btn dads-btn--secondary dads-btn--sm"
                        onClick={() => copyText(createdClient.client_secret ?? "", "client_secret")}
                      >
                        コピー
                      </button>
                    )}
                  </dd>
                </dl>
              </section>
            )}

            {/* Section 1: OAuth クライアント管理 */}
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">OAuth クライアント管理</h2>
                <p className="dads-lead">
                  この IdP を利用する外部アプリケーション（Relying
                  Party）の登録と一覧確認を行います。
                </p>

                <form className="dads-form" onSubmit={handleCreateClient}>
                  <div className="dads-field">
                    <label className="dads-label" htmlFor="client-name">
                      クライアント名<span className="dads-req">※必須</span>
                    </label>
                    <input
                      id="client-name"
                      type="text"
                      className="dads-input"
                      value={clientName}
                      onChange={(e) => setClientName(e.target.value)}
                      placeholder="例: My Local App"
                    />
                  </div>

                  <div className="dads-field">
                    <label className="dads-label" htmlFor="redirect-uris">
                      リダイレクト URI<span className="dads-req">※必須</span>
                    </label>
                    <p className="dads-support-text">複数指定する場合は改行で区切ってください。</p>
                    <textarea
                      id="redirect-uris"
                      className="dads-textarea"
                      value={redirectUrisText}
                      onChange={(e) => setRedirectUrisText(e.target.value)}
                    />
                  </div>

                  <label className="dads-checkbox-row">
                    <input
                      type="checkbox"
                      checked={isConfidential}
                      onChange={(e) => setIsConfidential(e.target.checked)}
                    />
                    <span>コンフィデンシャルクライアントとして登録（client_secret を発行）</span>
                  </label>

                  <div className="dads-btn-group">
                    <button
                      type="submit"
                      className="dads-btn dads-btn--primary"
                      aria-busy={busyAction === "create_client"}
                    >
                      {busyAction === "create_client" ? "登録中..." : "クライアントを登録"}
                    </button>
                  </div>
                </form>
              </div>

              <div className="dads-card__sub">
                <h3 className="dads-heading-3">登録済みクライアント ({clients.length})</h3>
                {clients.length === 0 ? (
                  <p className="dads-subtext">登録済みクライアントはありません。</p>
                ) : (
                  <ul className="dads-client-list">
                    {clients.map((c) => (
                      <li key={c.id} className="dads-client-item">
                        <div className="dads-client-item__head">
                          <span className="dads-client-item__name">{c.name}</span>
                          <button
                            type="button"
                            className="dads-btn dads-btn--secondary dads-btn--sm"
                            onClick={() => copyText(c.id, "client_id")}
                          >
                            ID をコピー
                          </button>
                        </div>
                        <div className="dads-subtext">
                          client_id: <span className="dads-mono">{c.id}</span>
                        </div>
                        <ul className="dads-uri-list">
                          {c.redirect_uris.map((uri) => (
                            <li key={uri}>{uri}</li>
                          ))}
                        </ul>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>

            {/* Section 2: ユーザー登録 */}
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">ユーザー登録</h2>
                <p className="dads-lead">
                  ログイン画面（/authorize）やマイページで認証できる IdP アカウントを作成します。
                </p>
                <form className="dads-form" onSubmit={handleRegisterUser}>
                  <div className="dads-field">
                    <label className="dads-label" htmlFor="reg-username">
                      ユーザー名<span className="dads-req">※必須</span>
                    </label>
                    <input
                      id="reg-username"
                      type="text"
                      className="dads-input"
                      autoComplete="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                    />
                  </div>

                  <div className="dads-field">
                    <label className="dads-label" htmlFor="reg-password">
                      パスワード<span className="dads-req">※必須</span>
                    </label>
                    <input
                      id="reg-password"
                      type="password"
                      className="dads-input"
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>

                  <label className="dads-checkbox-row">
                    <input
                      type="checkbox"
                      checked={grantAdmin}
                      onChange={(e) => setGrantAdmin(e.target.checked)}
                    />
                    <span>管理者権限を付与する</span>
                  </label>

                  <div className="dads-btn-group">
                    <button
                      type="submit"
                      className="dads-btn dads-btn--primary"
                      aria-busy={busyAction === "register_user"}
                    >
                      {busyAction === "register_user" ? "登録中..." : "ユーザーを登録"}
                    </button>
                  </div>
                </form>
              </div>
            </section>

            {/* Section 3: OIDC Discovery */}
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">OIDC エンドポイント情報</h2>
                {discovery ? (
                  <>
                    <dl className="dads-dl">
                      <dt>Issuer</dt>
                      <dd className="dads-mono">{discovery.issuer}</dd>
                      <dt>Authorization</dt>
                      <dd className="dads-mono">{discovery.authorization_endpoint}</dd>
                      <dt>Token</dt>
                      <dd className="dads-mono">{discovery.token_endpoint}</dd>
                      <dt>UserInfo</dt>
                      <dd className="dads-mono">{discovery.userinfo_endpoint}</dd>
                      <dt>Revocation</dt>
                      <dd className="dads-mono">{discovery.revocation_endpoint}</dd>
                      <dt>JWKS</dt>
                      <dd className="dads-mono">{discovery.jwks_uri}</dd>
                    </dl>
                    <details className="dads-details">
                      <summary>Discovery メタデータ (JSON) を表示</summary>
                      <pre className="dads-code-block">{JSON.stringify(discovery, null, 2)}</pre>
                    </details>
                  </>
                ) : (
                  <p className="dads-subtext">Discovery メタデータを取得できませんでした。</p>
                )}
              </div>
            </section>
          </>
        )}
      </main>

      <footer className="dads-footer">
        <p style={{ margin: 0 }}>Rust IdP Project — OAuth 2.0 / OpenID Connect Provider</p>
      </footer>
    </div>
  );
}
