import React, { useState } from 'react';
import { login, find, scan, signUp, getAllScans } from '../dataHelper';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [searchName, setSearchName] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [scanId, setScanId] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [userScans, setUserScans] = useState(null);

  const handleLogin = async () => {
    const success = await login(username, password);
    if (success) {
        console.log("Log in Successfully")
    } else {
        console.log("Failed to log in")
    }
  };

  const handleFind = async () => {
    const result = await find(searchName);
    if (result) {
        setSearchResult(result);
    } else {
        console.log("Couldn't find user")
    }
  };

  const handleScan = async () => {
    const result = await scan(scanId);
    if (result) {
        setScanResult(result);
    } else {
        console.log("Couldn't find scan id")
    }
  };

  const handleSignUp = async () => {
    const success = await signUp(username, password);
    if (success) {
        console.log("Sign Up Successfully")
    } else {
        console.log("Failed to Sign Up")
    }
  };

  const handleGetUserScans = async () => {
    const scans = await getAllScans(username);
    if (scans) {
        setUserScans(scans);
    } else {
        console.log("Failed to get user scans")
    }
  };

  return (
    <div>
      <h1>Login</h1>
      <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleLogin}>Login</button>

      <h1>Sign Up</h1>
      <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleSignUp}>Sign Up</button>

      <h1>Find</h1>
      <input type="text" placeholder="Name to search" value={searchName} onChange={(e) => setSearchName(e.target.value)} />
      <button onClick={handleFind}>Find</button>
      {searchResult && <div>{JSON.stringify(searchResult)}</div>}

      <h1>Scan</h1>
      <input type="text" placeholder="ID of scan" value={scanId} onChange={(e) => setScanId(e.target.value)} />
      <button onClick={handleScan}>Scan</button>
      {scanResult && <div>{JSON.stringify(scanResult)}</div>}

      <h1>User Scans</h1>
      <button onClick={handleGetUserScans}>Get User Scans</button>
      {userScans && <div>{JSON.stringify(userScans)}</div>}
    </div>
  );
}

export default App;
