import React, { useState } from 'react';

function DeviceForm(props) {
  const { username } = props
  const findID = async (e) => {
    try {
        const response = await fetch(`http://localhost:4000/server/find/${username}`);
        if (response.ok) {
          const data = await response.json();
          console.log(data.user_id)
          setUserID(data.user_id);
        } else {
          console.error('Failed to fetch ID:', response.statusText);
        }
      } catch (error) {
        console.error('Error fetching ID', error);
      }
    };
  
  const [userID, setUserID] = useState('')
  const [type, setType] = useState('');
  const [name, setName] = useState('');
  const [deviceId, setDeviceId] = useState(null);

  const handleTypeChange = (e) => {
    setType(e.target.value);
  };

  const handleNameChange = (e) => {
    setName(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    // Generate device ID (for demo purposes, you can use any logic here)
    const generatedId = "80" + Math.floor(Math.random() * 1000) + "05";
    setDeviceId(generatedId);
    await findID()
    // Prepare device data to be sent
    const deviceData = {
      type: type,
      name: name,
      id: generatedId,
      user_id: userID
    };
    // Send POST request to the server
    try {
      const response = await fetch('http://localhost:4000/server/add/device', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(deviceData)
      });
      if (response.ok) {
        console.log('Device added successfully!');
        // Reset form fields after successful submission
        setType('');
        setName('');
      } else {
        console.error('Failed to add device');
      }
    } catch (error) {
      console.error('Network error:', error);
    }
  };

  return (
    <div className="card">
      <div className="card-header">Add Device</div>
      <div className="card-body">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="type">Type:</label>
            <input type="text" className="form-control" id="type" value={type} onChange={handleTypeChange} required />
          </div>
          <div className="form-group">
            <label htmlFor="name">Name:</label>
            <input type="text" className="form-control" id="name" value={name} onChange={handleNameChange} required />
          </div>
          <button type="submit" className="btn btn-primary">Submit</button>
        </form>
      </div>
    </div>
  );
}

export default DeviceForm;
