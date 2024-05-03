import React from "react";
import PropTypes from 'prop-types'

export default function DeleteDeviceForm(props) {
    const {userID, onDeviceDeleted} = props 
  // State for device deletion form
  const [devicesToDelete, setDevicesToDelete] = React.useState({
    ip_add: '',
    userID: userID
  });

    // Handler for adding devices to delete list
    const handleAddDeviceToDelete = (deviceIp) => {
        setDevicesToDelete((prevState) => ({...prevState, ip_add: deviceIp}));
      };
       
      // Handler for submitting device deletion form
      const handleSubmitDeviceDeletion = async (e) => {
        e.preventDefault();
        // Logic for submitting device deletion form datatry {
      const response = await fetch('http://localhost:4000/server/device/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ip_add: devicesToDelete.ip_add
        })
      });
      if (response.ok) {
        alert('Device delete successfully!');
        onDeviceDeleted()
      } else {
        alert('Failed to delete device');
      }
      };
    
    return(
        <div className="card">
            <div className="card-header">Delete Devices</div>
            <div className="card-body">
            
              <form onSubmit={handleSubmitDeviceDeletion}>
                <div className="form-group">
                  <label htmlFor="deviceId">Device ip:</label>
                  <input
                    type="text"
                    className="form-control"
                    id="ip_add"
                    name="ip_add"
                    onChange={(e) => handleAddDeviceToDelete(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-danger">Delete Device</button>
              </form>
            </div>
          </div>
    )
}

DeleteDeviceForm.propTypes = {
  userID: PropTypes.string.isRequired
}