import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Eye, EyeOff, LogIn, UserPlus, AlertCircle, Loader2 } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function AuthPage() {
  const { signIn, signUp } = useAuth();
  const navigate = useNavigate();

  const [mode, setMode] = useState('login'); // 'login' | 'signup'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setLoading(true);
    try {
      if (mode === 'login') {
        await signIn({ email, password });
        navigate('/');
      } else {
        if (!fullName.trim()) {
          setError('Full name is required.');
          setLoading(false);
          return;
        }
        const res = await signUp({ email, password, fullName: fullName.trim() });
        if (res?.session) {
          // Direct login (Email Confirmation is disabled in Supabase)
          navigate('/');
        } else {
          // Email confirmation is enabled in Supabase
          setSuccessMsg('Account created! If email confirmation is enabled in your Supabase project, check your inbox/spam folder. Otherwise, you can sign in directly.');
          setMode('login');
          setPassword('');
          setFullName('');
        }
      }
    } catch (err) {
      setError(err.message ?? 'An unexpected error occurred.');
    } finally {
      setLoading(false);
    }
  }

  function switchMode() {
    setError('');
    setSuccessMsg('');
    setMode(m => (m === 'login' ? 'signup' : 'login'));
  }

  return (
    <div className="auth-page">
      {/* Ambient grid background */}
      <div className="auth-grid-bg" aria-hidden="true" />

      {/* Card */}
      <div className="auth-card glass-panel">
        {/* Header */}
        <div className="auth-card-header">
          <div className="auth-logo-wrap">
            <img src="/Specula_logo.png" alt="Specula" className="auth-logo" />
          </div>
          <h1 className="auth-title">SPECULA</h1>
          <p className="auth-subtitle">Multi-Agent DFIR Platform</p>
        </div>

        {/* Tab toggle */}
        <div className="auth-tabs" role="tablist">
          <button
            id="tab-login"
            role="tab"
            aria-selected={mode === 'login'}
            className={`auth-tab ${mode === 'login' ? 'auth-tab--active' : ''}`}
            onClick={() => { setMode('login'); setError(''); setSuccessMsg(''); }}
            type="button"
          >
            <LogIn size={15} />
            Sign In
          </button>
          <button
            id="tab-signup"
            role="tab"
            aria-selected={mode === 'signup'}
            className={`auth-tab ${mode === 'signup' ? 'auth-tab--active' : ''}`}
            onClick={() => { setMode('signup'); setError(''); setSuccessMsg(''); }}
            type="button"
          >
            <UserPlus size={15} />
            Create Account
          </button>
        </div>

        {/* Form */}
        <form className="auth-form" onSubmit={handleSubmit} noValidate>
          {mode === 'signup' && (
            <div className="auth-field">
              <label htmlFor="auth-fullname" className="auth-label">Full Name</label>
              <input
                id="auth-fullname"
                type="text"
                className="auth-input"
                placeholder="Jane Doe"
                value={fullName}
                onChange={e => setFullName(e.target.value)}
                required
                autoComplete="name"
              />
            </div>
          )}

          <div className="auth-field">
            <label htmlFor="auth-email" className="auth-label">Email Address</label>
            <input
              id="auth-email"
              type="email"
              className="auth-input"
              placeholder="investigator@specula.io"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>

          <div className="auth-field">
            <label htmlFor="auth-password" className="auth-label">Password</label>
            <div className="auth-input-wrap">
              <input
                id="auth-password"
                type={showPassword ? 'text' : 'password'}
                className="auth-input auth-input--padded-right"
                placeholder={mode === 'signup' ? 'Min. 6 characters' : '••••••••'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                minLength={6}
                autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
              />
              <button
                type="button"
                className="auth-eye-btn"
                onClick={() => setShowPassword(v => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Inline role badge for signup */}
          {mode === 'signup' && (
            <div className="auth-role-badge">
              <ShieldCheck size={14} />
              <span>Default role: <strong>Investigator</strong></span>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="auth-alert auth-alert--error" role="alert">
              <AlertCircle size={15} />
              <span>{error}</span>
            </div>
          )}

          {/* Success */}
          {successMsg && (
            <div className="auth-alert auth-alert--success" role="status">
              <ShieldCheck size={15} />
              <span>{successMsg}</span>
            </div>
          )}

          <button
            id="auth-submit-btn"
            type="submit"
            className="primary-btn auth-submit"
            disabled={loading}
          >
            {loading
              ? <><Loader2 size={16} className="auth-spinner" /> Processing…</>
              : mode === 'login'
                ? <><LogIn size={16} /> Sign In</>
                : <><UserPlus size={16} /> Create Account</>
            }
          </button>
        </form>

        {/* Footer switch */}
        <p className="auth-switch">
          {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
          {' '}
          <button type="button" className="auth-switch-btn" onClick={switchMode}>
            {mode === 'login' ? 'Sign up' : 'Sign in'}
          </button>
        </p>

        {/* Branding stripe */}
        <div className="auth-footer-stripe">
          <ShieldCheck size={12} />
          <span>Secure · Zero-Trust · OCSF Compliant</span>
        </div>
      </div>
    </div>
  );
}
