import React, { useState } from 'react';
import PropTypes from 'prop-types'

// Search component
function SearchPage(props) {
  const userID = props
  // State to hold the user input
  const [searchTerm, setSearchTerm] = useState('');
  const [result, setResult] = useState("");
  const [found, setFound] = useState(false)
  const [searchOption, setSearchOption] = useState('UserID'); // Default search option
 
  const handleSearchOptionChange = (event) => {
    setSearchOption(event.target.value);
  };
  // Function to handle input change
  const handleInputChange = (event) => {
    setSearchTerm(event.target.value);
  };
  // Function to handle search button click
  const handleSearch =
    async (e) => {
        e.preventDefault();
        try {
          let response
          if (searchOption === "NetworkID") {
            response = await fetch(`http://localhost:4000/server/find/scan/network/${searchTerm}`)
          } else if (searchOption == "UserID") {
            response = await fetch(`http://localhost:4000/server/find/scan/user/${userID}`)
          } else {
            response = await fetch(`http://localhost:4000/server/scan/${searchTerm}`)
          }
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
  let ind = 0;
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
            {
            Array.isArray(result) ? (
            result.map((scan, i) => (
            Array.isArray(scan.result) ? (
            scan.result.map((item, index) => (
              <tr key={index}>
                <td>{scan.userID}</td>
                <td>{scan.networkID}</td>
                <td>{scan.scanID}</td>
                <td>{item.host_num}</td>
                <td>{item.state}</td>
                <td>{item.ports.length}</td>
              </tr>
            ))) : (
              Array.isArray(result.result) ? (
              result.result.map((item, index) => (
              <tr key={index}>
              <td>{result.userID}</td>
              <td>{result.networkID}</td>
              <td>{result.scanID}</td>
              <td>{item.host_num}</td>
              <td>{item.state}</td>
              <td>{item.ports.length}</td>
            </tr>))) : (<tr>
              <td>{result.userID}</td>
              <td>{result.networkID}</td>
              <td>{result.scanID}</td>
              <td>{result.result.host_num}</td>
              <td>{result.result.state}</td>
              <td>{result.result.ports.length}</td>
            </tr>)
          )))) : (
                Array.isArray(result.result) ? (
                result.result.map((item, index) => (
                <tr key={index}>
                <td>{result.userID}</td>
                <td>{result.networkID}</td>
                <td>{result.scanID}</td>
                <td>{item.host_num}</td>
                <td>{item.state}</td>
                <td>{item.ports.length}</td>
              </tr>))) : (<tr>
                <td>{result.userID}</td>
                <td>{result.networkID}</td>
                <td>{result.scanID}</td>
                <td>{result.result.host_num}</td>
                <td>{result.result.state}</td>
                <td>{result.result.ports.length}</td>
              </tr>)
            )
           }
            </tbody>
            </table>   
            </div>
    )
  }
  return (
    <div className="card">
    <div className="card-header">
    <select value={searchOption} onChange={handleSearchOptionChange}>
          <option value="UserID">User ID</option>
          <option value="NetworkID">Network ID</option>
          <option value="ScanID">Scan ID</option>
    </select>
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
SearchPage.propTypes = {
  userID: PropTypes.string.isRequired
}
export default SearchPage
