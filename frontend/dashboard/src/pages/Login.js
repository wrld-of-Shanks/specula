import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (e) => {
    e.preventDefault();
    // Simple auth - just navigate to dashboard
    navigate('/dashboard');
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'white',
      fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '400px',
        padding: '40px',
        background: 'white',
        borderRadius: '12px',
        boxShadow: '0 4px 24px rgba(0,0,0,0.08)',
        border: '1px solid #e5e5e5'
      }}>
        <h1 style={{
          fontSize: '28px',
          fontWeight: '600',
          color: '#111',
          marginBottom: '8px',
          textAlign: 'center'
        }}>
          Specula
        </h1>
        <p style={{
          fontSize: '14px',
          color: '#666',
          marginBottom: '32px',
          textAlign: 'center'
        }}>
          Sign in to continue
        </p>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '20px' }}>
            <label style={{
              display: 'block',
              fontSize: '13px',
              fontWeight: '500',
              color: '#333',
              marginBottom: '6px'
            }}>
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              style={{
                width: '100%',
                padding: '12px 14px',
                fontSize: '14px',
                border: '1px solid #ddd',
                borderRadius: '8px',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
              onFocus={(e) => e.target.style.borderColor = '#0053de'}
              onBlur={(e) => e.target.style.borderColor = '#ddd'}
            />
          </div>

          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              fontSize: '13px',
              fontWeight: '500',
              color: '#333',
              marginBottom: '6px'
            }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              style={{
                width: '100%',
                padding: '12px 14px',
                fontSize: '14px',
                border: '1px solid #ddd',
                borderRadius: '8px',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
              onFocus={(e) => e.target.style.borderColor = '#0053de'}
              onBlur={(e) => e.target.style.borderColor = '#ddd'}
            />
          </div>

          <button
            type="submit"
            style={{
              width: '100%',
              padding: '12px',
              fontSize: '14px',
              fontWeight: '600',
              color: 'white',
              background: '#0053de',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              transition: 'background 0.2s'
            }}
            onMouseOver={(e) => e.target.style.background = '#0048c4'}
            onMouseOut={(e) => e.target.style.background = '#0053de'}
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login;
