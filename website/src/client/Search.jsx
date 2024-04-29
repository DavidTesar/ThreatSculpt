// Importing React library
import React, { useState } from 'react';

// Search component
function SearchPage() {
  // State to hold the user input
  const [searchTerm, setSearchTerm] = useState('');
  const [result, setResult] = useState("");
  const [found, setFound] = useState(false)
  // Function to handle input change
  const handleInputChange = (event) => {
    setSearchTerm(event.target.value);
  };
  // Function to handle search button click
  const handleSearch =
    async (e) => {
        e.preventDefault();
        try {
          const response = await fetch(`http://localhost:4000/server/scan/${searchTerm}`)
          if (response.ok) {
            const jsonData = await response.json();
            console.log(jsonData)
            setResult(jsonData);
            setFound(true)
          } else {
            setResult("Something went wrong");
          }
        } catch (error) {
          console.error('Network error:', error);
          setResult('Network error. Please try again later.');
        }
  }
  let content = null
  if (found) {
    content = (
         <div>
            <table className="table my-0" id="dataTable">
            <thead>
              <tr>
                <th>User ID</th>
                <th>Network ID</th>
                <th>Scan ID</th>
                <th>Host num</th>
                <th>State</th>
                <th>Ports</th>
              </tr>
            </thead>
            <tbody>
            {result.result.map((item, index) => (
                <tr>
                  <td>{result.userID}</td>
                  <td> {result.networkID}</td>
                  <td> {result.scanID} </td>
                  <td> {result.result[0].host_num}</td>
                  <td> {result.result[0].state}</td>
                  <td> {result.result[0].ports.length}</td>
                </tr>))}
            </tbody>
            </table>   
            </div>
    )
  }
  return (
    <div className="card">
    <div className="card-header">
    <input
        type="text"
        placeholder="Enter your search query..."
        value={searchTerm}
        onChange={handleInputChange}
      />
      <button onClick={handleSearch}>Search</button>
    </div>
    <div className="card-body">
    <div>
      {content}
    </div>
    </div>
  </div>
   
  );
}

export default SearchPage
