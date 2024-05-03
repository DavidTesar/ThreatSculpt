import React, { useState, useEffect } from 'react';
import DeleteDeviceForm from './Forms/DeleteDeviceForm';
import DeleteNetworkForm from './Forms/DeleteNetworkForm';
import AddDeviceForm from './Forms/AddDeviceForm';
import AddNetworkForm from './Forms/AddNetworkForm';
import UserInfoForm from './Forms/UserInfoForm';
import PropTypes from 'prop-types';

const SettingsPage = (props) => {
  const { user_id, setIsLoggedIn } = props;
  const [deviceList, setDeviceList] = useState([]);
  const [networkList, setNetworkList] = useState([]);
  const [isNet, setIsNet] = useState(false);
  const [isDev, setIsDev] = useState(false);

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const response = await fetch('http://localhost:4000/server/devices', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userID: user_id }),
        });

        if (response.ok) {
          const data = await response.json();
          setDeviceList(data);
          setIsDev(data.length > 0);
        } else {
          console.error('Failed to fetch device list:', response.status, response.statusText);
        }
      } catch (error) {
        console.error('Failed to fetch device list:', error.message);
      }
    };

    fetchDevices();
  }, [user_id]);

  useEffect(() => {
    const fetchNetworks = async () => {
      try {
        const response = await fetch('http://localhost:4000/server/networks', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userID: user_id }),
        });

        if (response.ok) {
          const data = await response.json();
          setNetworkList(data);
          setIsNet(data.length > 0);
        } else {
          console.error('Failed to fetch network list:', response.status, response.statusText);
        }
      } catch (error) {
        console.error('Failed to fetch network list:', error.message);
      }
    };

    fetchNetworks();
  }, [user_id]);

  const handleNetworkAdded = () => {
    // Call fetchNetworks to update the list of networks
    const fetchNetworks = async () => {
      try {
        const response = await fetch('http://localhost:4000/server/networks', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userID: user_id }),
        });

        if (response.ok) {
          const data = await response.json();
          setNetworkList(data);
          setIsNet(data.length > 0);
        } else {
          console.error('Failed to fetch network list:', response.status, response.statusText);
        }
      } catch (error) {
        console.error('Failed to fetch network list:', error.message);
      }
    };

    fetchNetworks();
  };

  const handleNetworkDeleted = async () => {
    try {
      const response = await fetch('http://localhost:4000/server/networks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userID: user_id }),
      });
  
      if (response.ok) {
        const data = await response.json();
        setNetworkList(data);
        setIsNet(data.length > 0);
      } else {
        console.error('Failed to fetch network list:', response.status, response.statusText);
      }
    } catch (error) {
      console.error('Failed to fetch network list:', error.message);
    }
  };

  const handleDevice = () => {
    // Call fetchDevices to update the list of devices
    const fetchDevices = async () => {
      try {
        const response = await fetch('http://localhost:4000/server/devices', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userID: user_id }),
        });

        if (response.ok) {
          const data = await response.json();
          setDeviceList(data);
          setIsDev(data.length > 0);
        } else {
          console.error('Failed to fetch device list:', response.status, response.statusText);
        }
      } catch (error) {
        console.error('Failed to fetch device list:', error.message);
      }
    };

    fetchDevices();
  };

  return (
    <div className="container">
      <div className="row">
          <UserInfoForm setIsLoggedIn={setIsLoggedIn} />
        </div>
        <div className="row">
          <div className="card">
            <div className="card-header">Network Operations</div>
            <div className="card-body">
            <div className="row">
              {isNet && (
                  <div className="col-md-4">
                    <ul>
                      {networkList.map((network, index) => (
                        <li key={index}>{network.networkID}</li>
                      ))}
                    </ul>
                  </div>
                  
              )}
              {!isNet && <div className="col-md-4">No Networks to display</div>}
              <div className="col-md-4">
                    <AddNetworkForm userID={user_id} onNetworkAdded={handleNetworkAdded} />
                  </div>
                  <div className="col-md-4">
                  <DeleteNetworkForm onNetworkDeleted={handleNetworkDeleted} />
                  </div>
                </div>
            </div>
        </div>
        </div>
        <div className="row">
          <div className="card">
            <div className="card-header">Device Operations</div>
            <div className="card-body">
            <div className="row">
              {isDev && (
                  <div className="col-md-4">
                    <ul>
                      {deviceList.map((dev, index) => (
                        <li key={index}>{dev.ip_add}</li>
                      ))}
                    </ul>
                  </div>
                  
              )}
              {!isDev &&
              <div className="col-md-4"> 
              No Devices to display</div>}
              <div className="col-md-4">
                    <AddDeviceForm user_id={user_id} onDeviceAdded = {handleDevice} />
                  </div>
                  <div className="col-md-4">
                    <DeleteDeviceForm userID={user_id} onDeviceDeleted = {handleDevice} />
                  </div>
                </div>
            </div>
          </div>
        </div>
    </div>
  );
};

SettingsPage.propTypes = {
  user_id: PropTypes.string.isRequired,
  setIsLoggedIn: PropTypes.func
};

export default SettingsPage;
