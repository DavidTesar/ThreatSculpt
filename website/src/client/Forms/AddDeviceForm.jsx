import React, { useState } from 'react';
import PropTypes from 'prop-types';

function AddDeviceForm(props) {
  const { user_id, onDeviceAdded } = props;
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
    // Prepare device data to be sent
    const deviceData = {
      ip_add: type,
      user_id: user_id,
      dev_id: generatedId
    };
    console.log(deviceData)
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
        alert('Device added successfully!');
        onDeviceAdded()
        // Reset form fields after successful submission
        setType('');
      } else {
        alert('Failed to add device');
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
AddDeviceForm.propTypes = {
  user_id: PropTypes.string.isRequired
}
export default AddDeviceForm;
