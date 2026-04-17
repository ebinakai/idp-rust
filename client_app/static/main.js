document.addEventListener("DOMContentLoaded", () => {
  document
    .getElementById("login-form")
    .addEventListener("submit", async (e) => {
      console.debug("submit button clicked!");
      e.preventDefault();
      const errorMsg = document.getElementById("error-message");
      errorMsg.textContent = "";

      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      
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

  document.getElementById("logout-button").addEventListener("click", () => {
    localStorage.removeItem("access_token");
    document.getElementById("login-section").style.display = "block";
    document.getElementById("result-section").style.display = "none";
    document.getElementById("login-form").reset();
  });

  function showResult(token) {
    document.getElementById("login-section").style.display = "none";
    document.getElementById("result-section").style.display = "block";
    document.getElementById("token-display").value = token;
  }

  
  if (localStorage.getItem("access_token")) {
    showResult(localStorage.getItem("access_token"));
  } else {
    console.debug("No access token found in localStorage");
  }
});
