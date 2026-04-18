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
        console.debug(data);
        if (data.refresh_token) {
          localStorage.setItem("refresh_token", data.refresh_token);
        }
        showResult(data.access_token);
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
      alert(err.message);
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
      const display = document.querySelector("#verify-local-result");
      display.style.display = "block";
      display.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      alert(err.message);
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
      const display = document.querySelector("#refresh-display");
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
      alert(err.message);
    }
  });
  
  document.querySelector("#logout-button").addEventListener("click", () => {
    localStorage.removeItem("access_token");
    document.querySelector("#login-section").style.display = "block";
    document.querySelector("#result-section").style.display = "none";
    document.querySelector("#login-form").reset();
  });

  function showResult(token) {
    document.querySelector("#login-section").style.display = "none";
    document.querySelector("#result-section").style.display = "block";
    document.querySelector("#token-display").value = token;
  }

  
  if (localStorage.getItem("access_token")) {
    showResult(localStorage.getItem("access_token"));
  } else {
    console.debug("No access token found in localStorage");
  }
});
