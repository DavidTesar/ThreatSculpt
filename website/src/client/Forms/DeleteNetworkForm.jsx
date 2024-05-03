import React from 'react'
import PropTypes from 'prop-types'
export default function DeleteNetworkForm (props) {
    const {onNetworkDeleted} = props
  // State for network deletion form
  const [networksToDelete, setNetworksToDelete] = React.useState('');


  // Handler for adding networks to delete list
  const handleAddNetworkToDelete = (networkID) => {
    setNetworksToDelete(networkID);
  };


  // Handler for submitting network deletion form
  const handleSubmitNetworkDeletion = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:4000/server/network/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({networkID: networksToDelete}),
      });

      if (response.ok) {
        // Show a success message if the network is added successfully
        alert('Network deleted successfully!');
        onNetworkDeleted()
      } else {
        // Show an error message if there is an issue adding the network
        alert('Error: Failed to delete network');
      }
    } catch (error) {
      console.error('Error:', error.message);
      // Show an error message if there is an exception
      alert('Error: Failed to delete network');
    }
  };
    return(
        <div className="card">
            <div className="card-header">Delete Networks</div>
            <div className="card-body">
              <form onSubmit={handleSubmitNetworkDeletion}>
               
                <div className="form-group">
                  <label htmlFor="networkId">Network ID: </label>
                  <input
                    type="text"
                    className="form-control"
                    id="networkID"
                    name="networkID"
                    onChange={(e) => handleAddNetworkToDelete(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-danger">Delete Network</button>
              </form>
            </div>
          </div>
    )
}