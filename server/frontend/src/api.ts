import type { CreationChallengeJson, RequestChallengeJson } from "./webauthn";

export interface OAuthClientItem {
  id: string;
  name: string;
  redirect_uris: string[];
  client_secret?: string;
}

export interface CreateClientReq {
  name: string;
  redirect_uris: string[];
  is_confidential: boolean;
}

export interface OpenIdConfig {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  scopes_supported: string[];
  code_challenge_methods_supported: string[];
  [key: string]: unknown;
}

export interface AuthContextRes {
  client_id: string;
  client_name: string;
  scopes: string[];
}

export type AuthActionRes =
  | { status: "redirect"; redirect_uri: string }
  | { status: "consent"; client_name: string; username: string; scopes: string[] };

export interface PasskeySummary {
  id: string;
  label: string;
  created_at?: string | null;
}

export interface UserConsentItem {
  client_id: string;
  client_name: string;
  created_at?: string | null;
}

export interface MeRes {
  needs_setup: boolean;
  logged_in: boolean;
  user?: {
    id: string;
    username: string;
    is_admin: boolean;
  };
  passkeys: PasskeySummary[];
  consents: UserConsentItem[];
}

interface OAuthErrorBody {
  error?: string;
  error_description?: string;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  const text = await res.text();
  if (!res.ok) {
    try {
      const parsed = JSON.parse(text) as OAuthErrorBody;
      if (parsed.error_description) {
        throw new Error(`${parsed.error ?? res.status}: ${parsed.error_description}`);
      }
    } catch (e) {
      if (e instanceof Error && e.message !== text && !e.message.startsWith("Unexpected")) {
        throw e;
      }
    }
    throw new Error(`${res.status} ${res.statusText}${text ? `: ${text}` : ""}`);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

export function fetchOpenIdConfig(): Promise<OpenIdConfig> {
  return requestJson<OpenIdConfig>("/.well-known/openid-configuration");
}

export function listClients(): Promise<OAuthClientItem[]> {
  return requestJson<OAuthClientItem[]>("/api/admin/clients");
}

export function createClient(req: CreateClientReq): Promise<OAuthClientItem> {
  return requestJson<OAuthClientItem>("/api/admin/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export function registerUser(username: string, password: string, isAdmin = false): Promise<void> {
  return requestJson<void>("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, is_admin: isAdmin }),
  });
}

export function fetchAuthContext(): Promise<AuthContextRes> {
  return requestJson<AuthContextRes>("/api/auth/context");
}

export function submitLogin(username: string, password: string): Promise<AuthActionRes> {
  return requestJson<AuthActionRes>("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

export function submitConsent(action: "allow" | "deny"): Promise<AuthActionRes> {
  return requestJson<AuthActionRes>("/consent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });
}

export function fetchMe(): Promise<MeRes> {
  return requestJson<MeRes>("/api/me");
}

export function accountLogin(username: string, password: string): Promise<void> {
  return requestJson<void>("/api/me/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

export function accountLogout(): Promise<void> {
  return requestJson<void>("/api/me/logout", { method: "POST" });
}

export function revokeConsent(clientId: string): Promise<void> {
  return requestJson<void>(`/api/me/consents/${encodeURIComponent(clientId)}`, {
    method: "DELETE",
  });
}

export function startPasskeyRegister(label?: string): Promise<CreationChallengeJson> {
  return requestJson<CreationChallengeJson>("/api/me/passkeys/register/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label: label?.trim() || null }),
  });
}

export function finishPasskeyRegister(credential: unknown): Promise<PasskeySummary> {
  return requestJson<PasskeySummary>("/api/me/passkeys/register/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credential),
  });
}

export function deletePasskey(id: string): Promise<void> {
  return requestJson<void>(`/api/me/passkeys/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function startPasskeyAuth(username: string): Promise<RequestChallengeJson> {
  return requestJson<RequestChallengeJson>("/api/passkey/auth/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });
}

export function finishPasskeyAuth(
  credential: unknown,
  mode: "account" | "authorize",
): Promise<AuthActionRes | { status: "ok" }> {
  return requestJson<AuthActionRes | { status: "ok" }>("/api/passkey/auth/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential, mode }),
  });
}
