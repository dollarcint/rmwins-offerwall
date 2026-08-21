import { ArrowLeft, ArrowRight, Eye, EyeOff, LockKeyhole, ShieldCheck } from 'lucide-react';
import { FormEvent, useEffect, useMemo, useState } from 'react';

type SessionResponse = {
  authenticated: boolean;
  csrf_token?: string;
  redirect_url?: string;
};

type LoginResponse = {
  authenticated?: boolean;
  redirect_url?: string;
  error?: string;
};

function getDashboardBaseUrl() {
  const configuredBase = import.meta.env.VITE_DASHBOARD_URL;
  if (configuredBase) return configuredBase.replace(/\/$/, '');

  const legacyLoginUrl = import.meta.env.VITE_DASHBOARD_LOGIN_URL;
  if (legacyLoginUrl) {
    return new URL(legacyLoginUrl, window.location.origin).origin;
  }

  return import.meta.env.DEV ? 'http://127.0.0.1:8000' : window.location.origin;
}

function getSafeNextUrl(dashboardBaseUrl: string) {
  const requested = new URLSearchParams(window.location.search).get('next');
  if (!requested) return '';

  try {
    const dashboardOrigin = new URL(dashboardBaseUrl).origin;
    const resolved = new URL(requested, `${dashboardOrigin}/`);
    return resolved.origin === dashboardOrigin ? resolved.toString() : '';
  } catch {
    return '';
  }
}

export default function LoginPage() {
  const dashboardBaseUrl = useMemo(getDashboardBaseUrl, []);
  const nextUrl = useMemo(() => getSafeNextUrl(dashboardBaseUrl), [dashboardBaseUrl]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [csrfToken, setCsrfToken] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();

    fetch(`${dashboardBaseUrl}/api/v1/auth/session/`, {
      credentials: 'include',
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not start a secure login session.');
        return response.json() as Promise<SessionResponse>;
      })
      .then((session) => {
        if (session.authenticated && session.redirect_url) {
          window.location.replace(nextUrl || session.redirect_url);
          return;
        }
        if (!session.csrf_token) throw new Error('Could not start a secure login session.');
        setCsrfToken(session.csrf_token);
      })
      .catch((requestError: Error) => {
        if (requestError.name !== 'AbortError') {
          setError('Login service is temporarily unavailable. Please try again.');
        }
      });

    return () => controller.abort();
  }, [dashboardBaseUrl, nextUrl]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');

    if (!csrfToken) {
      setError('Secure login is still loading. Please try again in a moment.');
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await fetch(`${dashboardBaseUrl}/api/v1/auth/login/`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken,
        },
        body: JSON.stringify({ username, password, remember_me: rememberMe }),
      });
      const isJson = response.headers.get('content-type')?.includes('application/json');
      const result = isJson
        ? ((await response.json()) as LoginResponse)
        : ({
            authenticated: false,
            error:
              response.status === 429
                ? 'Too many login attempts. Please try again later.'
                : response.status === 413
                  ? 'The login request is too large.'
                  : 'Unable to sign in right now. Please try again.',
          } satisfies LoginResponse);

      if (!response.ok || !result.authenticated) {
        setError(result.error || 'Username or password is incorrect.');
        return;
      }

      window.location.assign(nextUrl || result.redirect_url || `${dashboardBaseUrl}/`);
    } catch {
      setError('Unable to sign in right now. Please check your connection and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-50 lg:grid lg:grid-cols-[minmax(0,1.05fr)_minmax(440px,0.95fr)]">
      <section className="relative hidden overflow-hidden bg-brand-900 px-12 py-10 text-white lg:flex lg:flex-col lg:justify-between">
        <div className="absolute -left-28 top-20 h-80 w-80 rounded-full bg-brand-500/20 blur-3xl" />
        <div className="absolute -bottom-32 right-0 h-96 w-96 rounded-full bg-sky-300/10 blur-3xl" />

        <a href="/" className="relative z-10 inline-flex items-center gap-3 text-lg font-semibold">
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-white text-sm font-bold text-brand-900">RW</span>
          RM Wins Offerwall
        </a>

        <div className="relative z-10 max-w-xl">
          <p className="mb-5 text-sm font-semibold uppercase tracking-[0.2em] text-sky-200">Offerwall operations</p>
          <h1 className="text-5xl font-semibold leading-tight tracking-tight">Secure inventory, verified rewards and publisher delivery.</h1>
          <p className="mt-6 max-w-lg text-lg leading-relaxed text-slate-300">
            Manage publishers, live offers, respondent journeys, rewards and signed postbacks from one workspace.
          </p>
        </div>

        <div className="relative z-10 flex items-center gap-2 text-sm text-slate-300">
          <ShieldCheck size={18} className="text-sky-300" />
          Protected with role-based access
        </div>
      </section>

      <section className="flex min-h-screen items-center justify-center px-5 py-10 sm:px-10">
        <div className="w-full max-w-md">
          <a href="/" className="mb-10 inline-flex items-center gap-2 text-sm font-medium text-slate-500 transition-colors hover:text-brand-700 lg:hidden">
            <ArrowLeft size={16} /> Back to RM Wins Offerwall
          </a>

          <div className="mb-8">
            <div className="mb-5 grid h-12 w-12 place-items-center rounded-2xl bg-brand-50 text-brand-700">
              <LockKeyhole size={22} />
            </div>
            <p className="mb-2 text-sm font-semibold uppercase tracking-[0.16em] text-brand-700">Welcome back</p>
            <h2 className="text-3xl font-semibold tracking-tight text-slate-900">Sign in to your account</h2>
            <p className="mt-3 text-slate-500">Enter the credentials provided by your workspace administrator.</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {error}
              </div>
            )}

            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-700">Username</span>
              <input
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                autoFocus
                maxLength={150}
                required
                className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-slate-900 outline-none transition focus:border-brand-500 focus:ring-4 focus:ring-brand-50"
                placeholder="Enter your username"
              />
            </label>

            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-700">Password</span>
              <span className="relative block">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  maxLength={1024}
                  required
                  className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 pr-12 text-slate-900 outline-none transition focus:border-brand-500 focus:ring-4 focus:ring-brand-50"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((visible) => !visible)}
                  className="absolute inset-y-0 right-0 grid w-12 place-items-center text-slate-400 transition hover:text-slate-700"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </span>
            </label>

            <label className="flex cursor-pointer items-center gap-3 text-sm text-slate-600">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(event) => setRememberMe(event.target.checked)}
                className="h-4 w-4 rounded border-slate-300 text-brand-700 focus:ring-brand-500"
              />
              Keep me signed in
            </label>

            <button
              type="submit"
              disabled={isSubmitting || !csrfToken}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-brand-700 px-5 py-3.5 font-semibold text-white transition hover:bg-brand-600 focus:outline-none focus:ring-4 focus:ring-brand-100 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSubmitting ? 'Signing in…' : 'Sign in'}
              {!isSubmitting && <ArrowRight size={18} />}
            </button>
          </form>

          <p className="mt-8 text-center text-sm text-slate-500">
            Need workspace access? Contact your administrator.
          </p>
        </div>
      </section>
    </main>
  );
}
