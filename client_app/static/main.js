document.addEventListener("DOMContentLoaded", () => {
  document.querySelector("#login-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const errorMsg = document.querySelector("#error-message");
      errorMsg.textContent = "";

      const username = document.querySelector("#username").value;
      const password = document.querySelector("#password").value;
      
      try {
        const response = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        if (!response.ok) throw new Error("ログインに失敗しました");

        const data = await response.json();
        localStorage.setItem("access_token", data.access_token);
        if (data.id_token) localStorage.setItem("id_token", data.id_token);
        if (data.refresh_token) localStorage.setItem("refresh_token", data.refresh_token);
        showToken();
      } catch (err) {
        errorMsg.textContent = err.message;
      }
    });
  
  document.querySelector("#get-userinfo-button").addEventListener("click", async () => {
    const token = localStorage.getItem("access_token");
    if (!token) return;
    
    try {
      const response = await fetch("/api/userinfo", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      
      if (!response.ok) throw new Error("ユーザー情報の取得に失敗しました");
      
      const data = await response.json();
      const display = document.querySelector("#userinfo-display");
      display.style.display = "block";
      display.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      console.error(err.message);
    }
    
  });
  
  document.querySelector("#verify-local-button").addEventListener("click", async () => {
    const token = localStorage.getItem("access_token");
    if (!token) return;
    
    try {
      const response = await fetch("/api/verify", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      
      const data = await response.json();
      const display = document.querySelector("#verify-local-display");
      display.style.display = "block";
      display.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      console.error(err.message);
    }
  });

  document.querySelector("#refresh-button").addEventListener("click", async () => {
    const refreshToken = localStorage.getItem("refresh_token");
    if (!refreshToken) return;
    
    try {
      const response = await fetch("/api/refresh", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ refresh_token: refreshToken })
      });
      
      const data = await response.json();
      const display = document.querySelector("#refresh-token-display");
      display.style.display = "block";
      
      if (response.ok) {
        localStorage.setItem("access_token", data.access_token);
        if (data.refreshToken) {
          localStorage.setItem("refresh_token", data.refresh_token);
        }
        display.textContent = JSON.stringify(data, null, 2);
      } else {
        display.textContent = `エラー\n${response.status}\n${JSON.stringify(data, null, 2)}`;
      }
    } catch (err) {
      console.error(err.message);
    }
  });
  
  document.querySelector("#logout-button").addEventListener("click", async () => {
    const refreshToken = localStorage.getItem("refresh_token");
    
    if (refreshToken) {
      try {
        await fetch("/api/logout", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ refresh_token: refreshToken })
        });
      } catch (err) {
        console.error("バックエンドのログアウト処理でエラー:", err);
      }
    }
    
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    document.querySelector("#login-section").style.display = "block";
    document.querySelector("#result-section").style.display = "none";
    document.querySelector("#login-form").reset();
    
    document.querySelector("#token-display").value = "";
    document.querySelector("#id-token-display").textContent = "";
    document.querySelector("#userinfo-display").textContent = "";
    document.querySelector("#verify-local-display").textContent = "";
    document.querySelector("#refresh-token-display").textContent = "";
  });

  function showToken() {
    document.querySelector("#login-section").style.display = "none";
    document.querySelector("#result-section").style.display = "block";
    if (localStorage.getItem("id_token")) {
      const decodedIdToken = parseJwt(localStorage.getItem("id_token"));
      document.querySelector("#id-token-display").textContent = JSON.stringify(decodedIdToken, null, 2);
    }
    document.querySelector("#token-display").value = localStorage.getItem("access_token");
  }
  
  function parseJwt(token) {
      try {
          // トークンをピリオドで分割し、ペイロード部分（[1]）を取得
          const base64Url = token.split('.')[1];
          // Base64Url形式を標準のBase64形式に変換
          const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
          // デコード処理（マルチバイト文字対応）
          const jsonPayload = decodeURIComponent(atob(base64).split('').map((c) =>
            `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`
          ).join(''));
  
          return JSON.parse(jsonPayload);
      } catch (e) {
          console.error("JWTのデコードに失敗しました", e);
          return null;
      }
  }

  if (localStorage.getItem("access_token")) {
    showToken();
  } else {
    console.debug("No access token found in localStorage");
  }
});
