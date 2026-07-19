const authForm = document.getElementById("authForm");
const submitBtn = document.getElementById("submitBtn");
const confirmGroup = document.getElementById("confirmGroup");
const confirmPasswordInput = document.getElementById("confirmPassword");
const messageDiv = document.getElementById("message");
const switchHint = document.getElementById("switchHint");
const switchLink = document.getElementById("switchLink");
const tabs = document.querySelectorAll(".tab");

let currentMode = "login";

async function initAuthPage() {
  const user = await getCurrentUser();
  if (user) {
    window.location.href = "dashboard.html";
    return;
  }

  setMode(currentMode);
}

function setMode(mode) {
  currentMode = mode;
  tabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.tab === mode);
  });

  if (mode === "signup") {
    confirmGroup.classList.remove("hidden");
    confirmPasswordInput.required = true;
    submitBtn.textContent = "Sign Up";
    switchHint.textContent = "Already have an account? ";
    switchLink.textContent = "Login here";
  } else {
    confirmGroup.classList.add("hidden");
    confirmPasswordInput.required = false;
    submitBtn.textContent = "Login";
    switchHint.textContent = "Don't have an account? ";
    switchLink.textContent = "Sign up here";
  }

  hideMessage();
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => setMode(tab.dataset.tab));
});

switchLink.addEventListener("click", (e) => {
  e.preventDefault();
  setMode(currentMode === "login" ? "signup" : "login");
});

function showMessage(text, type = "error") {
  messageDiv.textContent = text;
  messageDiv.className = `message ${type}`;
  messageDiv.classList.remove("hidden");
}

function hideMessage() {
  messageDiv.classList.add("hidden");
  messageDiv.textContent = "";
}

authForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideMessage();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  submitBtn.disabled = true;
  const originalText = submitBtn.textContent;
  submitBtn.textContent = "Loading...";

  try {
    if (currentMode === "signup") {
      const confirmPassword = confirmPasswordInput.value;
      if (password !== confirmPassword) {
        showMessage("Passwords do not match.", "error");
        return;
      }

      const { data, error } = await sb.auth.signUp({ email, password });
      if (error) throw error;

      if (data.user && !data.session) {
        showMessage("Check your email to confirm your account.", "success");
      } else {
        showMessage("Signup successful! Redirecting...", "success");
        window.location.href = "dashboard.html";
      }
    } else {
      const { data, error } = await sb.auth.signInWithPassword({
        email,
        password,
      });
      if (error) throw error;

      if (data.session) {
        showMessage("Login successful! Redirecting...", "success");
        window.location.href = "dashboard.html";
      } else {
        showMessage("Unable to sign in right now.", "error");
      }
    }
  } catch (err) {
    showMessage(err.message || "Something went wrong.", "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
});

initAuthPage();

// Google Sign In handler
const googleBtn = document.getElementById("googleSignInBtn");
if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    hideMessage();
    googleBtn.disabled = true;
    const original = googleBtn.innerHTML;
    googleBtn.innerHTML = "Redirecting to Google...";

    try {
      const { error } = await sb.auth.signInWithOAuth({
        provider: "google",
        options: {
          redirectTo: `${window.location.origin}/dashboard.html`,
        },
      });

      if (error) throw error;
    } catch (err) {
      showMessage("Google login failed: " + err.message, "error");
      googleBtn.disabled = false;
      googleBtn.innerHTML = original;
    }
  });
}
