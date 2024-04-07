import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [username, setUsername] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    // Fetch username from server
    const fetchUsername = async () => {
      try {
        const response = await fetch('http://localhost:4000/get-username');
        if (response.ok) {
          const data = await response.json();
          setUsername(data.username);
          setIsLoggedIn(true);
        } else {
          console.error('Failed to fetch username:', response.statusText);
        }
      } catch (error) {
        console.error('Error fetching username:', error);
      }
    };

    fetchUsername();
  }, []);

  return (
    <div className="App">
      {isLoggedIn ? <h2>Hello: {username}</h2> : <h2>Please log in</h2>}
    </div>
  );
}

export default App;