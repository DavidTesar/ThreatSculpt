import React, { useState, useEffect } from 'react';
import './App.css';

function RandomNumbers() {
  const [numbers, setNumbers] = useState([]);

  useEffect(() => {
    const generateNumbers = () => {
      const newNumbers = [];
      for (let i = 0; i < 20; i++) {
        const randomNumber = Math.floor(Math.random() * 10) + 1; // Generate random numbers between 1 and 10
        newNumbers.push(randomNumber);
      }
      setNumbers(newNumbers);
    };
    
    generateNumbers();
  }, []);

  return (
    <div>
      {numbers.map((number, index) => (
        <div key={index} style={{ position: 'absolute', top: `${Math.random() * 90}vh`, left: `${Math.random() * 90}vw`}} className={number > 6 ? 'highlighted' : ''}>
          {number}
        </div>
      ))}
    </div>
  );
}

function HighlightableText({ text }) {
  const [highlightedText, setHighlightedText] = useState('');

  useEffect(() => {
    // Highlight numbers above 6 when the component mounts
    handleHighlightNumbers(); 
  }, [text]); // Trigger highlighting when the text prop changes

  const handleHighlightNumbers = () => {
    // Logic to highlight numbers greater than a threshold (e.g., 6)
    const highlighted = text.replace(/\b(\d+)\b/g, (match, number) => {
      if (parseInt(number) > 6) {
        return `<span class='highlighted'>${number}</span>`;
      } else {
        return number;
      }
    });
    setHighlightedText(highlighted);
  };

  return (
    <div>
      <style>
        {`
        p {
          color: white;
        }

          .highlighted {
            background-color: red; /* Highlight the text with red background */
            color: white; /* Set the text color to white */
            font-weight: bold;
          }
        `}
      </style>
    </div>
  );
}

function App() {
  const exampleText = "This is an example text with numbers like 6, 7, 8, 9, and 10.";
  return (
    <div>
          <video className="video-background" autoPlay loop muted>
      <source src="https://brown-friendly-dragon-577.mypinata.cloud/ipfs/QmZJ8Xj8NnMU6EoEoPYPMuk1M1aQ9JiUrCsAR7YsieLkfc" type="video/mp4" />
      Your browser does not support the video tag.
    </video>
      <div>
      <RandomNumbers />
      <HighlightableText text={exampleText} />
      </div>
    </div>
  );
}

export default App;