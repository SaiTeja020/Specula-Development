import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { Activity, LayoutDashboard, Database, Network, Server, Play, ShieldAlert } from 'lucide-react';
import LandingPage from './pages/LandingPage';
import StartupPage from './pages/StartupPage';
import InvestigationConsole from './pages/InvestigationConsole';
import Neo4jVisualizer from './pages/Neo4jVisualizer';
import DatabaseVisualizers from './pages/DatabaseVisualizers';

function Sidebar() {
  const location = useLocation();

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
        <img src="/specula-logo.svg" alt="Specula Logo" style={{ height: '32px' }} />
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
        <div className="status-indicator">
          <div className="status-dot"></div>
          <span>System Online</span>
        </div>
      </div>
    </aside>
  );
}

function Layout({ children }) {
  const location = useLocation();
  // Don't show sidebar on landing page or startup page if desired, but we will show it everywhere for easy navigation.
  const isFullscreenRoute = location.pathname === '/' || location.pathname === '/startup';

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
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/startup" element={<StartupPage />} />
          <Route path="/investigate" element={<InvestigationConsole />} />
          <Route path="/neo4j" element={<Neo4jVisualizer />} />
          <Route path="/databases" element={<DatabaseVisualizers />} />
        </Routes>
      </Layout>
    </Router>
  );
}
