document.addEventListener("DOMContentLoaded", async () => {
  const loginSection = document.querySelector("#login-section");
  const resultSection = document.querySelector("#result-section");
  const tokenDisplay = document.querySelector("#token-display");
  const idTokenDisplay = document.querySelector("#id-token-display");
  const userinfoDisplay = document.querySelector("#userinfo-display");
  const verifyDisplay = document.querySelector("#verify-local-display");
  const refreshDisplay = document.querySelector("#refresh-token-display");

  function showSession(data) {
    loginSection.style.display = "none";
    resultSection.style.display = "block";
    tokenDisplay.value = data.access_token || "";
    if (data.id_token) {
      const decoded = parseJwt(data.id_token);
      idTokenDisplay.textContent = JSON.stringify(decoded, null, 2);
    } else {
      idTokenDisplay.textContent = "(none)";
    }
  }

  function showLoggedOut() {
    loginSection.style.display = "block";
    resultSection.style.display = "none";
    tokenDisplay.value = "";
    idTokenDisplay.textContent = "";
    userinfoDisplay.textContent = "";
    verifyDisplay.textContent = "";
    refreshDisplay.textContent = "";
  }

  function parseJwt(token) {
    try {
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
          .join("")
      );
      return JSON.parse(jsonPayload);
    } catch (e) {
      console.error("JWTのデコードに失敗しました", e);
      return null;
    }
  }

  document.querySelector("#get-userinfo-button").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/userinfo", { method: "GET" });
      const text = await response.text();
      userinfoDisplay.style.display = "block";
      userinfoDisplay.textContent = response.ok
        ? JSON.stringify(JSON.parse(text), null, 2)
        : `エラー (${response.status})\n${text}`;
    } catch (err) {
      console.error(err.message);
    }
  });

  document.querySelector("#verify-local-button").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/verify", { method: "GET" });
      const text = await response.text();
      verifyDisplay.style.display = "block";
      verifyDisplay.textContent = response.ok
        ? JSON.stringify(JSON.parse(text), null, 2)
        : `エラー (${response.status})\n${text}`;
    } catch (err) {
      console.error(err.message);
    }
  });

  document.querySelector("#refresh-button").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/refresh", { method: "POST" });
      const text = await response.text();
      refreshDisplay.style.display = "block";

      if (response.ok) {
        const data = JSON.parse(text);
        tokenDisplay.value = data.access_token || "";
        refreshDisplay.textContent = JSON.stringify(data, null, 2);
      } else {
        refreshDisplay.textContent = `エラー (${response.status})\n${text}`;
      }
    } catch (err) {
      console.error(err.message);
    }
  });

  document.querySelector("#logout-button").addEventListener("click", async () => {
    try {
      await fetch("/api/logout", { method: "POST" });
    } catch (err) {
      console.error("バックエンドのログアウト処理でエラー:", err);
    }
    showLoggedOut();
  });

  try {
    const res = await fetch("/api/session");
    if (res.ok) {
      const session = await res.json();
      if (session.logged_in) {
        showSession(session);
        return;
      }
    }
  } catch (err) {
    console.error("セッション取得エラー:", err);
  }
  showLoggedOut();
});
