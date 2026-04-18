document.addEventListener("DOMContentLoaded", () => {
  document.querySelector("#login-form")
    .addEventListener("submit", async (e) => {
      console.debug("submit button clicked!");
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

        // JWTをブラウザのLocalStorageに保存してUIを切り替える
        localStorage.setItem("access_token", data.access_token);
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
  
  console.log(document.querySelector("#verify-local-button"));
  document.querySelector("#verify-local-button").addEventListener("click", async () => {
    console.debug("button clicked!");
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
