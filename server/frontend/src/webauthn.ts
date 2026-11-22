function base64UrlToUint8Array(base64Url: string): Uint8Array<ArrayBuffer> {
  const padded = base64Url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(base64Url.length / 4) * 4, "=");
  const binary = atob(padded);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function ensureWebAuthnSupported() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(
      "このブラウザまたは接続環境ではパスキー（WebAuthn）を利用できません。http://localhost または https:// でアクセスしてください。",
    );
  }
}

interface RawDescriptor {
  type: PublicKeyCredentialType;
  id: string;
  transports?: AuthenticatorTransport[];
}

export interface CreationChallengeJson {
  publicKey: Omit<
    PublicKeyCredentialCreationOptions,
    "challenge" | "user" | "excludeCredentials"
  > & {
    challenge: string;
    user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
    excludeCredentials?: RawDescriptor[];
  };
}

export interface RequestChallengeJson {
  publicKey: Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
    challenge: string;
    allowCredentials?: RawDescriptor[];
  };
}

export async function createPasskeyCredential(ccr: CreationChallengeJson): Promise<unknown> {
  ensureWebAuthnSupported();
  const pk = ccr.publicKey;
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...pk,
    challenge: base64UrlToUint8Array(pk.challenge),
    user: {
      ...pk.user,
      id: base64UrlToUint8Array(pk.user.id),
    },
    authenticatorSelection: {
      ...pk.authenticatorSelection,
      residentKey: "required",
      requireResidentKey: true,
    },
    excludeCredentials: pk.excludeCredentials?.map((item) => ({
      ...item,
      id: base64UrlToUint8Array(item.id),
    })),
  };

  const credential = (await navigator.credentials.create({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("パスキーの作成がキャンセルされました。");
  }

  const resp = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: arrayBufferToBase64Url(resp.attestationObject),
      clientDataJSON: arrayBufferToBase64Url(resp.clientDataJSON),
      transports: typeof resp.getTransports === "function" ? resp.getTransports() : undefined,
    },
    extensions: credential.getClientExtensionResults(),
  };
}

export async function getPasskeyAssertion(rcr: RequestChallengeJson): Promise<unknown> {
  ensureWebAuthnSupported();
  const pk = rcr.publicKey;
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...pk,
    challenge: base64UrlToUint8Array(pk.challenge),
    allowCredentials:
      pk.allowCredentials && pk.allowCredentials.length > 0
        ? pk.allowCredentials.map((item) => ({
            ...item,
            id: base64UrlToUint8Array(item.id),
          }))
        : undefined,
  };

  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("パスキーの認証がキャンセルされました。");
  }

  const resp = credential.response as AuthenticatorAssertionResponse;
  const userHandle =
    resp.userHandle && resp.userHandle.byteLength > 0
      ? arrayBufferToBase64Url(resp.userHandle)
      : null;

  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: arrayBufferToBase64Url(resp.authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(resp.clientDataJSON),
      signature: arrayBufferToBase64Url(resp.signature),
      userHandle,
    },
    extensions: credential.getClientExtensionResults(),
  };
}
