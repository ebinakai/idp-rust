import { type FormEvent, useEffect, useState } from "react";
import {
  fetchAuthContext,
  submitConsent,
  submitLogin,
  type AuthContextRes,
} from "./api";

type ConsentState = {
  client_name: string;
  username: string;
  scopes: string[];
};

export function AuthorizePage() {
  const [loading, setLoading] = useState(true);
  const [context, setContext] = useState<AuthContextRes | null>(null);
  const [consentData, setConsentData] = useState<ConsentState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    fetchAuthContext()
      .then((data) => setContext(data))
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "認可セッションの取得に失敗しました";
        setError(msg);
      })
      .finally(() => setLoading(false));
  }, []);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    if (busy) return;

    if (!username.trim() || !password) {
      setError("ユーザー名とパスワードを入力してください。");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const res = await submitLogin(username.trim(), password);
      if (res.status === "redirect") {
        window.location.assign(res.redirect_uri);
        return;
      }
      setConsentData({
        client_name: res.client_name,
        username: res.username,
        scopes: res.scopes,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "ログインに失敗しました";
      setError(msg);
    } finally {
      setBusy(false);
    }
  }

  async function handleConsent(action: "allow" | "deny") {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await submitConsent(action);
      if (res.status === "redirect") {
        window.location.assign(res.redirect_uri);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "認可処理に失敗しました";
      setError(msg);
      setBusy(false);
    }
  }

  const chipLabel = loading ? "確認中" : consentData ? "認可確認" : "ログイン";

  return (
    <div className="dads-page">
      <header className="dads-header">
        <div className="dads-header__inner">
          <h1 className="dads-header__title">Rust IdP</h1>
          <div className="dads-header__actions">
            <span className="dads-chip">{chipLabel}</span>
          </div>
        </div>
      </header>

      <main className="dads-auth-main">
        {error && (
          <div className="dads-notice dads-notice--error" role="status" aria-live="polite">
            <p className="dads-notice__title">認証エラー</p>
            <p className="dads-notice__body">{error}</p>
          </div>
        )}

        {loading ? (
          <section className="dads-card" aria-busy="true">
            <div className="dads-card__main">
              <p className="dads-lead">認可セッションを確認しています...</p>
            </div>
          </section>
        ) : consentData ? (
          <section className="dads-card">
            <div className="dads-card__main">
              <h2 className="dads-heading-2">{consentData.client_name}</h2>
              <p className="dads-lead">があなたのアカウントへのアクセスを求めています</p>

              <div className="dads-user-box">
                <p className="dads-subtext">ログイン中のアカウント</p>
                <strong>{consentData.username}</strong>
              </div>

              <p className="dads-label" style={{ marginBottom: 4 }}>
                以下の権限が共有されます：
              </p>
              <ul className="dads-scope-list">
                {consentData.scopes.map((scope) => (
                  <li key={scope}>{scope}</li>
                ))}
              </ul>

              <div className="dads-btn-group dads-btn-group--between">
                <button
                  type="button"
                  className="dads-btn dads-btn--secondary"
                  onClick={() => handleConsent("deny")}
                  aria-busy={busy}
                >
                  キャンセル
                </button>
                <button
                  type="button"
                  className="dads-btn dads-btn--primary"
                  onClick={() => handleConsent("allow")}
                  aria-busy={busy}
                >
                  {busy ? "処理中..." : "許可する"}
                </button>
              </div>
            </div>
          </section>
        ) : context ? (
          <section className="dads-card">
            <div className="dads-card__main">
              <h2 className="dads-heading-2">{context.client_name} がアクセスを求めています</h2>
              <p className="dads-lead">ログインして認可を完了してください。</p>

              <form className="dads-form" onSubmit={handleLogin}>
                <div className="dads-field">
                  <label className="dads-label" htmlFor="auth-username">
                    ユーザー名<span className="dads-req">※必須</span>
                  </label>
                  <input
                    id="auth-username"
                    type="text"
                    className="dads-input"
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>

                <div className="dads-field">
                  <label className="dads-label" htmlFor="auth-password">
                    パスワード<span className="dads-req">※必須</span>
                  </label>
                  <input
                    id="auth-password"
                    type="password"
                    className="dads-input"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>

                <div className="dads-btn-group">
                  <button
                    type="submit"
                    className="dads-btn dads-btn--primary"
                    aria-busy={busy}
                  >
                    {busy ? "認証中..." : "ログインして次へ"}
                  </button>
                </div>
              </form>
            </div>
          </section>
        ) : (
          <section className="dads-card">
            <div className="dads-card__main">
              <h2 className="dads-heading-2">認可セッションが無効です</h2>
              <p className="dads-lead">
                クライアントアプリケーションからログインフローをやり直してください。
              </p>
            </div>
          </section>
        )}
      </main>

      <footer className="dads-footer">
        <p style={{ margin: 0 }}>Rust IdP Project — OAuth 2.0 / OpenID Connect Provider</p>
      </footer>
    </div>
  );
}
