import React, { useState } from 'react';
import './App.css';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loggingIn, setLoggingIn] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoggingIn(true);
    try {
      const response = await fetch('http://localhost:4000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      if (response.ok) {
        // Login successful
        setLoginError('');
        setIsLoggedIn(true);
      } else {
        // Login failed
        const errorData = await response.json();
        setLoginError(errorData.error);
      }
    } catch (error) {
      console.error('Network error:', error);
      setLoginError('Network error. Please try again later.');
    }
    setLoggingIn(false);
  };

  return (
    <div className="login-container">
      <h2>{isLoggedIn ? `Welcome, ${username}!` : 'Login'}</h2>
      {!isLoggedIn && (
        <form onSubmit={handleLogin}>
          <div>
            <label htmlFor="username">Username:</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div>
            <label htmlFor="password">Password:</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" disabled={loggingIn}>
            {loggingIn ? 'Logging in...' : 'Login'}
          </button>
          {loginError && <div className="error-message">{loginError}</div>}
        </form>
      )}
    </div>
  );
}

export default App;