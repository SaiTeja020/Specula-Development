import { BrowserRouter as Router, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import { Activity, LayoutDashboard, Database, Network, Play, LogOut, ShieldCheck, User } from 'lucide-react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import LandingPage from './pages/LandingPage';
import StartupPage from './pages/StartupPage';
import InvestigationConsole from './pages/InvestigationConsole';
import Neo4jVisualizer from './pages/Neo4jVisualizer';
import DatabaseVisualizers from './pages/DatabaseVisualizers';
import AuthPage from './pages/AuthPage';

// Route guard – redirects unauthenticated users to /auth
function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return <div className="auth-loading"><span className="auth-loading-dot" /><span className="auth-loading-dot" /><span className="auth-loading-dot" /></div>;
  if (!isAuthenticated) return <Navigate to="/auth" replace />;
  return children;
}

function Sidebar() {
  const location = useLocation();
  const { profile, signOut } = useAuth();

  const links = [
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={18} /> },
    { to: '/startup', label: 'System Boot', icon: <Play size={18} /> },
    { to: '/investigate', label: 'Live Investigation', icon: <Activity size={18} /> },
    { to: '/neo4j', label: 'Knowledge Graph', icon: <Network size={18} /> },
    { to: '/databases', label: 'Data Stores', icon: <Database size={18} /> }
  ];

  return (
    <aside className="sidebar glass-panel">
      <div className="sidebar-brand">
        <img src="/Specula_logo.png" alt="Specula Logo" style={{ height: '32px' }} />
        <span>SPECULA</span>
      </div>
      <nav className="sidebar-nav">
        {links.map(link => (
          <Link
            key={link.to}
            to={link.to}
            className={`nav-item ${location.pathname === link.to ? 'active' : ''}`}
          >
            {link.icon}
            <span>{link.label}</span>
          </Link>
        ))}
      </nav>
      <div className="sidebar-footer">
        {/* User profile strip */}
        {profile && (
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">
              <User size={14} />
            </div>
            <div className="sidebar-user-info">
              <span className="sidebar-user-name">{profile.full_name}</span>
              <span className="sidebar-user-role">
                <ShieldCheck size={11} />
                {profile.role}
              </span>
            </div>
          </div>
        )}
        <div className="sidebar-footer-row">
          <div className="status-indicator">
            <div className="status-dot"></div>
            <span>System Online</span>
          </div>
          <button
            id="sidebar-signout-btn"
            className="sidebar-signout-btn"
            onClick={signOut}
            title="Sign out"
            type="button"
          >
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </aside>
  );
}

function Layout({ children }) {
  const location = useLocation();
  const isAuthRoute = location.pathname === '/auth';
  const isFullscreenRoute = location.pathname === '/' || location.pathname === '/startup';

  if (isAuthRoute) {
    return <div className="app-container-fullscreen">{children}</div>;
  }

  if (isFullscreenRoute) {
    return <div className="app-container-fullscreen">{children}</div>;
  }

  return (
    <div className="app-container-layout">
      <Sidebar />
      <main className="main-viewport">
        {children}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Layout>
          <Routes>
            {/* Public */}
            <Route path="/auth" element={<AuthPage />} />

            {/* Protected */}
            <Route path="/" element={<ProtectedRoute><LandingPage /></ProtectedRoute>} />
            <Route path="/startup" element={<ProtectedRoute><StartupPage /></ProtectedRoute>} />
            <Route path="/investigate" element={<ProtectedRoute><InvestigationConsole /></ProtectedRoute>} />
            <Route path="/neo4j" element={<ProtectedRoute><Neo4jVisualizer /></ProtectedRoute>} />
            <Route path="/databases" element={<ProtectedRoute><DatabaseVisualizers /></ProtectedRoute>} />

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout>
      </Router>
    </AuthProvider>
  );
}
