import { type FormEvent, useCallback, useEffect, useState } from "react";
import {
  accountLogin,
  accountLogout,
  deletePasskey,
  fetchMe,
  finishPasskeyAuth,
  finishPasskeyRegister,
  type MeRes,
  revokeConsent,
  startPasskeyAuth,
  startPasskeyRegister,
} from "./api";
import { createPasskeyCredential, getPasskeyAssertion } from "./webauthn";

interface NoticeState {
  kind: "info" | "success" | "error";
  title: string;
  body: string;
}

function formatDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("ja-JP");
}

export function AccountPage() {
  const [loading, setLoading] = useState(true);
  const [me, setMe] = useState<MeRes | null>(null);
  const [notice, setNotice] = useState<NoticeState | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  // Login form
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  // Passkey registration form
  const [passkeyLabel, setPasskeyLabel] = useState("");

  const reloadMe = useCallback(async () => {
    const data = await fetchMe();
    setMe(data);
  }, []);

  useEffect(() => {
    reloadMe()
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "アカウント情報の取得に失敗しました";
        setNotice({ kind: "error", title: "読み込みエラー", body: msg });
      })
      .finally(() => setLoading(false));
  }, [reloadMe]);

  async function handlePasswordLogin(e: FormEvent) {
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

    setBusyAction("login_pw");
    setNotice(null);
    try {
      await accountLogin(username.trim(), password);
      await reloadMe();
      setPassword("");
      setNotice({
        kind: "success",
        title: "ログインしました",
        body: "パスキーや連携済みアプリを管理できます。",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "ログインに失敗しました";
      setNotice({ kind: "error", title: "ログインエラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  async function handlePasskeyLogin() {
    if (busyAction) return;
    if (!username.trim()) {
      setNotice({
        kind: "error",
        title: "入力エラー",
        body: "パスキーでログインするにはユーザー名を入力してください。",
      });
      return;
    }

    setBusyAction("login_pk");
    setNotice(null);
    try {
      const rcr = await startPasskeyAuth(username.trim());
      const credential = await getPasskeyAssertion(rcr);
      await finishPasskeyAuth(credential, "account");
      await reloadMe();
      setNotice({
        kind: "success",
        title: "パスキーでログインしました",
        body: "生体認証・セキュリティキーによるサインインが完了しました。",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "パスキーログインに失敗しました";
      setNotice({ kind: "error", title: "パスキー認証エラー", body: msg });
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
      await reloadMe();
      setNotice({
        kind: "info",
        title: "ログアウトしました",
        body: "マイページからサインアウトしました。",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "ログアウトに失敗しました";
      setNotice({ kind: "error", title: "ログアウトエラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRegisterPasskey(e: FormEvent) {
    e.preventDefault();
    if (busyAction) return;

    setBusyAction("register_pk");
    setNotice(null);
    try {
      const ccr = await startPasskeyRegister(passkeyLabel);
      const credential = await createPasskeyCredential(ccr);
      const created = await finishPasskeyRegister(credential);
      setPasskeyLabel("");
      await reloadMe();
      setNotice({
        kind: "success",
        title: "パスキーを登録しました",
        body: `「${created.label}」をアカウントに紐づけました。`,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "パスキーの登録に失敗しました";
      setNotice({ kind: "error", title: "パスキー登録エラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleDeletePasskey(id: string, label: string) {
    if (busyAction) return;
    setBusyAction(`del_pk_${id}`);
    setNotice(null);
    try {
      await deletePasskey(id);
      await reloadMe();
      setNotice({
        kind: "info",
        title: "パスキーを削除しました",
        body: `「${label}」を削除しました。`,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "削除に失敗しました";
      setNotice({ kind: "error", title: "パスキー削除エラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRevokeConsent(clientId: string, clientName: string) {
    if (busyAction) return;
    setBusyAction(`rev_${clientId}`);
    setNotice(null);
    try {
      await revokeConsent(clientId);
      await reloadMe();
      setNotice({
        kind: "info",
        title: "アプリ連携を解除しました",
        body: `「${clientName}」への同意とリフレッシュトークンを取り消しました。`,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "連携解除に失敗しました";
      setNotice({ kind: "error", title: "連携解除エラー", body: msg });
    } finally {
      setBusyAction(null);
    }
  }

  const currentUser = me?.logged_in ? me.user : undefined;
  const loggedIn = Boolean(currentUser);

  return (
    <div className="dads-page">
      <header className="dads-header">
        <div className="dads-header__inner">
          <h1 className="dads-header__title">Rust IdP マイページ</h1>
          <div className="dads-header__actions">
            <span className={`dads-chip ${loggedIn ? "dads-chip--success" : ""}`}>
              {loading ? "確認中" : loggedIn ? "ログイン中" : "未ログイン"}
            </span>
            {(me?.user?.is_admin || me?.needs_setup) && (
              <a href="/" className="dads-btn dads-btn--secondary dads-btn--sm">
                管理ポータル
              </a>
            )}
            {loggedIn && (
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
              <p className="dads-lead">アカウント情報を読み込んでいます...</p>
            </div>
          </section>
        ) : !currentUser || !me ? (
          <>
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">マイページへログイン</h2>
                <p className="dads-lead">
                  登録済みパスキーの追加・削除や連携済みアプリの確認を行うにはログインしてください。
                </p>

                <form className="dads-form" onSubmit={handlePasswordLogin}>
                  <div className="dads-field">
                    <label className="dads-label" htmlFor="me-username">
                      ユーザー名<span className="dads-req">※必須</span>
                    </label>
                    <input
                      id="me-username"
                      type="text"
                      className="dads-input"
                      autoComplete="username webauthn"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                    />
                  </div>

                  <div className="dads-field">
                    <label className="dads-label" htmlFor="me-password">
                      パスワード
                    </label>
                    <p className="dads-support-text">
                      パスキーのみでログインする場合はパスワードの入力は不要です。
                    </p>
                    <input
                      id="me-password"
                      type="password"
                      className="dads-input"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>

                  <div className="dads-btn-group dads-btn-group--between">
                    <button
                      type="button"
                      className="dads-btn dads-btn--secondary"
                      onClick={handlePasskeyLogin}
                      aria-busy={busyAction === "login_pk"}
                    >
                      {busyAction === "login_pk" ? "認証中..." : "パスキーでログイン"}
                    </button>
                    <button
                      type="submit"
                      className="dads-btn dads-btn--primary"
                      aria-busy={busyAction === "login_pw"}
                    >
                      {busyAction === "login_pw" ? "ログイン中..." : "パスワードでログイン"}
                    </button>
                  </div>
                </form>
              </div>
            </section>

            <aside className="dads-notice dads-notice--info">
              <p className="dads-notice__title">パスキー（WebAuthn）の動作条件</p>
              <p className="dads-notice__body">
                ブラウザ仕様により、パスキーは <code>http://localhost</code> または{" "}
                <code>https://</code>{" "}
                環境でのみ動作します。初めて登録する場合はパスワードでログインしてください。
              </p>
            </aside>
          </>
        ) : (
          <>
            {/* Section 1: アカウント情報 */}
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">アカウント情報</h2>
                <dl className="dads-dl">
                  <dt>ユーザー名</dt>
                  <dd>{currentUser.username}</dd>
                  <dt>権限</dt>
                  <dd>{currentUser.is_admin ? "管理者" : "一般ユーザー"}</dd>
                  <dt>ユーザー ID (sub)</dt>
                  <dd className="dads-mono">{currentUser.id}</dd>
                </dl>
              </div>
            </section>

            {/* Section 2: パスキー管理 */}
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">パスキー管理</h2>
                <p className="dads-lead">
                  Touch ID・Windows
                  Hello・ハードウェアセキュリティキーなどを登録して、パスワードなしでログインできます。
                </p>

                <form className="dads-form" onSubmit={handleRegisterPasskey}>
                  <div className="dads-field">
                    <label className="dads-label" htmlFor="passkey-label">
                      パスキーの名前（任意）
                    </label>
                    <input
                      id="passkey-label"
                      type="text"
                      className="dads-input"
                      placeholder="例: MacBook Touch ID"
                      value={passkeyLabel}
                      onChange={(e) => setPasskeyLabel(e.target.value)}
                    />
                  </div>
                  <div className="dads-btn-group">
                    <button
                      type="submit"
                      className="dads-btn dads-btn--primary"
                      aria-busy={busyAction === "register_pk"}
                    >
                      {busyAction === "register_pk"
                        ? "デバイス待機中..."
                        : "このデバイスでパスキーを登録"}
                    </button>
                  </div>
                </form>
              </div>

              <div className="dads-card__sub">
                <h3 className="dads-heading-3">登録済みパスキー ({me.passkeys.length})</h3>
                {me.passkeys.length === 0 ? (
                  <p className="dads-subtext">登録済みのパスキーはありません。</p>
                ) : (
                  <ul className="dads-client-list">
                    {me.passkeys.map((pk) => (
                      <li key={pk.id} className="dads-client-item">
                        <div className="dads-client-item__head">
                          <span className="dads-client-item__name">{pk.label}</span>
                          <button
                            type="button"
                            className="dads-btn dads-btn--secondary dads-btn--sm"
                            onClick={() => handleDeletePasskey(pk.id, pk.label)}
                            aria-busy={busyAction === `del_pk_${pk.id}`}
                          >
                            削除
                          </button>
                        </div>
                        <div className="dads-subtext">
                          登録日時: {formatDateTime(pk.created_at)}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>

            {/* Section 3: 連携済みアプリ（同意管理） */}
            <section className="dads-card">
              <div className="dads-card__main">
                <h2 className="dads-heading-2">連携済みアプリ ({me.consents.length})</h2>
                <p className="dads-lead">
                  アクセスを許可した外部 OAuth
                  クライアントです。連携を解除するとリフレッシュトークンも失効します。
                </p>
                {me.consents.length === 0 ? (
                  <p className="dads-subtext">現在連携しているアプリはありません。</p>
                ) : (
                  <ul className="dads-client-list">
                    {me.consents.map((item) => (
                      <li key={item.client_id} className="dads-client-item">
                        <div className="dads-client-item__head">
                          <span className="dads-client-item__name">{item.client_name}</span>
                          <button
                            type="button"
                            className="dads-btn dads-btn--secondary dads-btn--sm"
                            onClick={() => handleRevokeConsent(item.client_id, item.client_name)}
                            aria-busy={busyAction === `rev_${item.client_id}`}
                          >
                            連携を解除
                          </button>
                        </div>
                        <div className="dads-subtext">
                          client_id: <span className="dads-mono">{item.client_id}</span>
                        </div>
                        <div className="dads-subtext">
                          許可日時: {formatDateTime(item.created_at)}
                        </div>
                      </li>
                    ))}
                  </ul>
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
