(function () {
  "use strict";
  // Bypass on localhost
  if (
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1"
  ) {
    return;
  }

  // ---------- Config ----------
  const REDIRECT_ON_DEVTOOLS = true; // Redirect if DevTools detected
  const REDIRECT_URL = "about:blank"; // Where to redirect on tampering
  const WARNING_MESSAGE = "Access Denied. Tampering detected.";

  // ---------- 1. Block right-click context menu ----------
  document.addEventListener(
    "contextmenu",
    function (e) {
      e.preventDefault();
      return false;
    },
    { capture: true },
  );

  // ---------- 2. Block keyboard shortcuts ----------
  document.addEventListener(
    "keydown",
    function (e) {
      // F12 - Open DevTools
      if (e.key === "F12" || e.keyCode === 123) {
        e.preventDefault();
        return false;
      }

      // Ctrl+Shift+I - Inspector
      if (e.ctrlKey && e.shiftKey && (e.key === "I" || e.keyCode === 73)) {
        e.preventDefault();
        return false;
      }

      // Ctrl+Shift+J - Console
      if (e.ctrlKey && e.shiftKey && (e.key === "J" || e.keyCode === 74)) {
        e.preventDefault();
        return false;
      }

      // Ctrl+Shift+C - Element inspector
      if (e.ctrlKey && e.shiftKey && (e.key === "C" || e.keyCode === 67)) {
        e.preventDefault();
        return false;
      }

      // Ctrl+U - View source
      if (e.ctrlKey && (e.key === "u" || e.key === "U" || e.keyCode === 85)) {
        e.preventDefault();
        return false;
      }

      // Ctrl+S - Save page
      if (e.ctrlKey && (e.key === "s" || e.key === "S" || e.keyCode === 83)) {
        e.preventDefault();
        return false;
      }

      // Ctrl+A - Select all (optional, comment out if you want to allow)
      // if (e.ctrlKey && (e.key === "a" || e.key === "A" || e.keyCode === 65)) {
      //   e.preventDefault();
      //   return false;
      // }

      // Ctrl+P - Print
      if (e.ctrlKey && (e.key === "p" || e.key === "P" || e.keyCode === 80)) {
        e.preventDefault();
        return false;
      }
    },
    { capture: true },
  );

  // ---------- 3. Detect DevTools open (via window size difference) ----------
  let devtoolsOpen = false;
  const threshold = 160;

  function detectDevTools() {
    const widthThreshold = window.outerWidth - window.innerWidth > threshold;
    const heightThreshold = window.outerHeight - window.innerHeight > threshold;

    if (widthThreshold || heightThreshold) {
      if (!devtoolsOpen) {
        devtoolsOpen = true;
        handleTampering("DevTools detected");
      }
    } else {
      devtoolsOpen = false;
    }
  }

  // ---------- 4. Detect DevTools via debugger timing ----------
  function detectDebugger() {
    const start = performance.now();
    // eslint-disable-next-line no-debugger
    debugger;
    const end = performance.now();

    if (end - start > 100) {
      handleTampering("Debugger detected");
    }
  }

  // ---------- 5. Detect console usage via getter trick ----------
  let consoleWarnCount = 0;
  const consoleTrap = {};
  Object.defineProperty(consoleTrap, "id", {
    get: function () {
      consoleWarnCount++;
      if (consoleWarnCount > 2) {
        handleTampering("Console inspection detected");
      }
      return "protected";
    },
  });

  // Try to trigger the trap by console.log-ing our object periodically
  setInterval(function () {
    console.log(consoleTrap);
    console.clear();
  }, 1000);

  // ---------- 6. Tampering handler ----------
  function handleTampering(reason) {
    if (REDIRECT_ON_DEVTOOLS) {
      document.body.innerHTML = "";
      document.title = "Access Denied";
      // Optional: log tampering attempt (fire-and-forget)
      try {
        console.warn(WARNING_MESSAGE, reason);
      } catch (e) {}
      // Redirect
      window.location.replace(REDIRECT_URL);
    }
  }

  // ---------- 7. Continuously check for DevTools ----------
  setInterval(detectDevTools, 500);
  setInterval(detectDebugger, 2000);

  // ---------- 8. Disable text selection (optional) ----------
  const style = document.createElement("style");
  style.textContent = `
    body {
      -webkit-user-select: none;
      -moz-user-select: none;
      -ms-user-select: none;
      user-select: none;
    }
    input, textarea {
      -webkit-user-select: text !important;
      -moz-user-select: text !important;
      -ms-user-select: text !important;
      user-select: text !important;
    }
  `;
  document.head.appendChild(style);

  // ---------- 9. Disable drag ----------
  document.addEventListener(
    "dragstart",
    function (e) {
      e.preventDefault();
      return false;
    },
    { capture: true },
  );

  // ---------- 10. Clear console periodically ----------
  setInterval(function () {
    try {
      console.clear();
    } catch (e) {}
  }, 3000);
})();
