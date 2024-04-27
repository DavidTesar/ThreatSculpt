import React from 'react'

export default function DeleteNetworkForm () {
    
  // State for network deletion form
  const [networksToDelete, setNetworksToDelete] = React.useState([]);


  // Handler for adding networks to delete list
  const handleAddNetworkToDelete = (networkId) => {
    setNetworksToDelete((prevState) => [...prevState, networkId]);
  };

  // Handler for removing networks from delete list
  const handleRemoveNetworkToDelete = (networkId) => {
    setNetworksToDelete((prevState) => prevState.filter(id => id !== networkId));
  };

  // Handler for submitting network deletion form
  const handleSubmitNetworkDeletion = (e) => {
    e.preventDefault();
    // Logic for submitting network deletion form data
    console.log('Networks to delete:', networksToDelete);
  };
    return(
        <div className="card">
            <div className="card-header">Delete Networks</div>
            <div className="card-body">
              <form onSubmit={handleSubmitNetworkDeletion}>
               
                <div className="form-group">
                  <label htmlFor="networkId">Host</label>
                  <input
                    type="text"
                    className="form-control"
                    id="host"
                    name="host"
                    onChange={(e) => handleAddNetworkToDelete(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-danger">Delete Network</button>
              </form>
            </div>
          </div>
    )
}