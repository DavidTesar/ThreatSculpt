import React from 'react'

export default function AddNetworkForm (props) {
    const {userID} = props
  // State for network deletion form
  const [networkstoAdd, setNetworkstoAdd] = React.useState({
    host: '',
    name: '',
    networkID: '',
    userID: userID
  });


  // Handler for adding networks to delete list
  const handleAddNetworktoAdd = (e) => {
    const {name, value} = e.target
    setNetworkstoAdd((prevState) => ({...prevState, [name]: value}));
  };

  // Handler for removing networks from delete list
  const handleRemoveNetworktoAdd = (networkId) => {
    setNetworkstoAdd((prevState) => prevState.filter(id => id !== networkId));
  };

  // Handler for submitting network deletion form
  const handleSubmitNetworkDeletion = (e) => {
    e.preventDefault();
    // Logic for submitting network deletion form data
    console.log('Networks to delete:', networkstoAdd);
  };
    return(
        <div className="card">
              <div className="card-header">Add Networks</div>
            <div className="card-body">
              <form onSubmit={handleSubmitNetworkDeletion}>
                <div className="form-group">
                  <label htmlFor="networkId">Network Host</label>
                  <input
                    type="text"
                    className="form-control"
                    id="host"
                    name="host"
                    onChange={(e) => handleAddNetworktoAdd(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="networkId">Network Name</label>
                  <input
                    type="text"
                    className="form-control"
                    id="name"
                    name="name"
                    onChange={(e) => handleAddNetworktoAdd(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-primary">Add Selected Networks</button>
              </form>
            </div>
          </div>
    )
}