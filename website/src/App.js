import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  // State to manage whether results are available
  const [resultsAvailable, setResultsAvailable] = useState(false);

  useEffect(() => {
    // Simulate fetching data or checking for results
    setTimeout(() => {
      setResultsAvailable(true);
    }, 8000); // Simulate a delay of 3 seconds
  }, []);

  return (
    <div className={`app-container ${resultsAvailable ? 'results-available' : 'no-results'}`}>
      <video className="video-background" autoPlay loop muted>
        <source src="https://brown-friendly-dragon-577.mypinata.cloud/ipfs/QmZJ8Xj8NnMU6EoEoPYPMuk1M1aQ9JiUrCsAR7YsieLkfc" type="video/mp4" />
        Your browser does not support the video tag.
      </video>
      <div className="content">
        <h1>Comming soon</h1>
        {!resultsAvailable && <p className="output">There's no result for the moment</p>}
      </div>
    </div>
  );
}

export default App;