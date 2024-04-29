//DELETE NETWORK AND USER AFTERWARD
import React from 'react';

export default function AddNetworkForm(props) {
  const { userID, onNetworkAdded } = props;

  // Function to generate a random network ID
  const generateRandomNetworkID = () => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const idLength = 16;
    let networkID = '';
    for (let i = 0; i < idLength; i++) {
      networkID += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return networkID;
  };

  // State for network addition form
  const [networkToAdd, setNetworkToAdd] = React.useState({
    host: [],
    networkID: generateRandomNetworkID(),
    userID: userID
  });

  // Function to handle submission of the network addition form
  const handleSubmitNetworkAddition = async (e) => {
    e.preventDefault();
    setNetworkToAdd((prevState)=> ({
      ...prevState,
      networkID: generateRandomNetworkID()
    }))
    try {
      const response = await fetch('http://localhost:4000/server/add/network', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(networkToAdd),
      });

      if (response.ok) {
        // Show a success message if the network is added successfully
        alert('Network added successfully!');
        onNetworkAdded()
      } else {
        // Show an error message if there is an issue adding the network
        alert('Error: Failed to add network');
      }
    } catch (error) {
      console.error('Error adding network:', error.message);
      // Show an error message if there is an exception
      alert('Error: Failed to add network');
    }
  };

  // Handler for dynamically adding input fields based on host number
  const handleHostNumberChange = (e) => {
    const hostNumber = parseInt(e.target.value);
    setNetworkToAdd((prevState) => ({
      ...prevState,
      host: Array.from({ length: hostNumber }, (_, index) => ({
        value: ''
      }))
    }));
  };

  // Handler for updating host values
  const handleHostChange = (index, value) => {
    setNetworkToAdd((prevState) => ({
      ...prevState,
      host: prevState.host.map((host, i) =>
        i === index ? { ...host, value: value } : host
      )
    }));
  };

  return (
    <div className="card">
      <div className="card-header">Add Networks</div>
      <div className="card-body">
        <form onSubmit={handleSubmitNetworkAddition}>
          <div className="form-group">
            <label htmlFor="hostNumber">Number of Hosts</label>
            <input
              type="number"
              className="form-control"
              id="hostNumber"
              name="hostNumber"
              onChange={handleHostNumberChange}
              min="1"
              step="1"
              required
            />
          </div>
          {networkToAdd.host.map((host, index) => (
            <div className="form-group" key={index}>
              <label htmlFor={`host-${index + 1}`}>Host {index + 1}</label>
              <input
                type="text"
                className="form-control"
                id={`host-${index + 1}`}
                name={`host-${index + 1}`}
                value={host.value}
                onChange={(e) => handleHostChange(index, e.target.value)}
                required
              />
            </div>
          ))}
          <button type="submit" className="btn btn-primary">Add Networks</button>
        </form>
      </div>
    </div>
  );
}
