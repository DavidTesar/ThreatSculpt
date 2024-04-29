import React, { useState } from 'react';

function AddDeviceForm(props) {
  const { username } = props
  const findID = async (e) => {
    try {
        const response = await fetch(`http://localhost:4000/server/find/${username}`);
        if (response.ok) {
          const data = await response.json();
          console.log(data.user_id)
          setUserID(data.user_id);
          return data.user_id
        } else {
          console.error('Failed to fetch ID:', response.statusText);
        }
      } catch (error) {
        console.error('Error fetching ID', error);
      }
    };
  
  const [userID, setUserID] = useState('')
  const [type, setType] = useState('');
  const [deviceId, setDeviceId] = useState(null);

  const handleTypeChange = (e) => {
    setType(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    // Generate device ID (for demo purposes, you can use any logic here)
    const generatedId = "80" + Math.floor(Math.random() * 1000) + "05";
    setDeviceId(generatedId);
    const user_id = await findID()
    setUserID(user_id)
    // Prepare device data to be sent
    const deviceData = {
      ip_add: type,
      user_id: user_id,
      deviceID: generatedId
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
            <label htmlFor="type">Ip Address:</label>
            <input type="text" className="form-control" id="type" value={type} onChange={handleTypeChange} required />
          </div>
          <button type="submit" className="btn btn-primary">Submit</button>
        </form>
      </div>
    </div>
  );
}

export default AddDeviceForm;
