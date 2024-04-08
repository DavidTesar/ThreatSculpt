import React, { useState, useEffect } from 'react';
import './App.css';


function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loggingIn, setLoggingIn] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userInfo, setUserInfo] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [userID, setUserID] = useState(null);

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
        const userData = await response.json();
        console.log('User Data:', userData);
        setUserID(userData.userID);
        console.log('User ID:', userData.userID);
        // Fetch user information after successful login
        const userInfoResponse = await fetch('http://localhost:4000/getUserInfo', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ username }), // Pass the username
        });
        if (userInfoResponse.ok) {
          const userInfoData = await userInfoResponse.json();
          console.log('User Info Data:', userInfoData);
          setUserInfo(userInfoData);
        } else {
          console.error('Failed to fetch user information');
        }
        // Fetch scan results after successful login
        const scanResultsResponse = await fetch('http://localhost:4000/getUserData', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userID }), // Pass the userID
        });
        if (scanResultsResponse.ok) {
          const scanResultsData = await scanResultsResponse.json();
          console.log('Scan Results Data:', scanResultsData);
          setScanResults(scanResultsData);
        } else {
          console.error('Failed to fetch scan results');
        }
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
      <h2>{isLoggedIn && userInfo ? `Welcome, ${userInfo.username}!` : 'Login'}</h2>
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

      {isLoggedIn && userInfo && (
        <div>
          {/* Add more user information here if needed */}
          <h3>Scan Results:</h3>
          <ul>
            {scanResults.map((result, index) => (
              <li key={index}>
                Scan ID: {result.scanID}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
} 

export default App;