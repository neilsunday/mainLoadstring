// ==========================================
// Supabase Client - Shared across all pages
// ==========================================

const SUPABASE_URL = "https://uwxsgijolhlpnihdelrq.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV3eHNnaWpvbGhscG5paGRlbHJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ0NTUyNTEsImV4cCI6MjEwMDAzMTI1MX0.CMNhOEN5Ll03ezQRND7w6Ji5NFvG5gzI1j8bf0wu_GI";

// Initialize Supabase client with proper OAuth handling
const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true, // auto-process #access_token=... from OAuth redirects
    flowType: "implicit", // for browser SPAs without server-side callback
  },
});

// Helper: wait for OAuth session hash to be processed (max 3 seconds)
async function waitForSession(maxWaitMs = 3000) {
  const start = Date.now();

  while (Date.now() - start < maxWaitMs) {
    const {
      data: { session },
    } = await sb.auth.getSession();
    if (session) return session;

    // If URL has no OAuth hash, no point waiting
    if (!window.location.hash.includes("access_token")) {
      return null;
    }

    // Wait 100ms then retry
    await new Promise((r) => setTimeout(r, 100));
  }

  return null;
}

// Helper: get current user (waits for OAuth if needed)
async function getCurrentUser() {
  const session = await waitForSession();
  return session?.user ?? null;
}

// Helper: redirect to login kung walang session
async function requireAuth() {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = "index.html";
    return null;
  }

  // Clean up OAuth hash from URL after successful auth
  if (window.location.hash.includes("access_token")) {
    history.replaceState(null, "", window.location.pathname);
  }

  return user;
}

// Helper: redirect to dashboard kung may session na (para sa login page)
async function redirectIfLoggedIn() {
  const user = await getCurrentUser();
  if (user) {
    window.location.href = "dashboard.html";
  }
}
