// ==========================================
// Supabase Client - Shared across all pages
// ==========================================

const SUPABASE_URL = "https://uwxsgijolhlpnihdelrq.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV3eHNnaWpvbGhscG5paGRlbHJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ0NTUyNTEsImV4cCI6MjEwMDAzMTI1MX0.CMNhOEN5Ll03ezQRND7w6Ji5NFvG5gzI1j8bf0wu_GI";

const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    flowType: "implicit",
  },
});

// Wait for OAuth session using onAuthStateChange event
async function waitForSession(maxWaitMs = 5000) {
  const hasOAuthHash = window.location.hash.includes("access_token");

  const {
    data: { session: existingSession },
  } = await sb.auth.getSession();
  if (existingSession) return existingSession;

  if (!hasOAuthHash) return null;

  console.log("Waiting for OAuth session...");

  return new Promise((resolve) => {
    let done = false;

    const {
      data: { subscription },
    } = sb.auth.onAuthStateChange((event, session) => {
      if (
        (event === "SIGNED_IN" || event === "INITIAL_SESSION") &&
        session &&
        !done
      ) {
        done = true;
        subscription.unsubscribe();
        console.log("Session ready");
        resolve(session);
      }
    });

    const interval = setInterval(async () => {
      const {
        data: { session },
      } = await sb.auth.getSession();
      if (session && !done) {
        done = true;
        clearInterval(interval);
        subscription.unsubscribe();
        resolve(session);
      }
    }, 200);

    setTimeout(() => {
      if (!done) {
        done = true;
        clearInterval(interval);
        subscription.unsubscribe();
        console.warn("Session wait timeout");
        resolve(null);
      }
    }, maxWaitMs);
  });
}

async function getCurrentUser() {
  const session = await waitForSession();
  return session?.user ?? null;
}

async function requireAuth() {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = "index.html";
    return null;
  }
  if (window.location.hash.includes("access_token")) {
    history.replaceState(null, "", window.location.pathname);
  }
  return user;
}

async function redirectIfLoggedIn() {
  const user = await getCurrentUser();
  if (user) {
    window.location.href = "dashboard.html";
  }
}
