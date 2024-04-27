import React, { useState } from 'react';
import DeviceForm from './Forms/AddDeviceForm';
import DeleteDeviceForm from './Forms/DeleteDeviceForm';
import DeleteNetworkForm from './Forms/DeleteNetworkForm';
import AddDeviceForm from './Forms/AddDeviceForm';
import AddNetworkForm from './Forms/AddNetworkForm';
import UserInfoForm from './Forms/UserInfoForm';
import PropTypes from 'prop-types'
import e from 'cors';
const SettingsPage = (props) => {
  const user_id = props
  const [deviceList, setDeviceList] = useState([])
  const [networkList, setNetworkList] = useState([])
  const [isNet, setIsNet] = useState(false)
  const [isDev, setIsDev] = useState(false)
  React.useEffect(() => {
    const fetchDeviceList = async () => {
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
          setDeviceList(data); // Update deviceList state with fetched data
          if(data.length === 0) {
            setIsDev(false)
          } else {
            setIsDev(true)
          }
        } else {
          console.error('Failed to fetch device list:', response.status, response.statusText);
        }
      } catch (error) {
        console.error('Failed to fetch device list:', error.message);
      }
    };

    fetchDeviceList(); // Call the fetchDeviceList function when the component mounts
  }, []); // Empty dependency array ensures this effect runs only once after initial render

  React.useEffect(() => {
    const fetchDeviceList = async () => {
      try {
        const response = await fetch('http://localhost:4000/server/networks', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userID: user_id}), 
        });
        if (response.ok) {
          const data = await response.json();
          setNetworkList(data); // Update deviceList state with fetched data
          if(data.length === 0) {
            setIsNet(false)
          } else {
            setIsNet(true)
          }
        } else {
          console.error('Failed to fetch device list:', response.status, response.statusText);
        }
      } catch (error) {
        console.error('Failed to fetch device list:', error.message);
      }
    };

    fetchDeviceList(); // Call the fetchDeviceList function when the component mounts
  }, []); // Empty dependency array ensures this effect runs only once after initial render
  let netCont = (<div> No Network to display </div>)
  if (isNet) {
    netCont = (
        <div className='card'>
        <div className='card-header'> List of Networks</div>
        <div className='card-body'>
        <ul>
        {networkList.map((network, index) => (
            <li key={index}>
                {network.name} : {network.host}
            </li>
        ))}
        </ul>
        </div>
        </div>
    )
  }

  let devCont = (<div>No device to display</div>)
  if (isDev) {
    devCont = (
        <div className='card'>
        <div className='card-header'> List of Devices</div>
        <div className='card-body'>
        <ul>
                {deviceList.map((dev, index) => (
                    <li key={index}>
                        {dev.ip_add}
                    </li>
                ))}
        </ul>
        </div>
        </div>
    )
  } 

  return (
    <div className="container">
      <div className="row">
        <div className="col-md-4">
        <UserInfoForm/>
        </div>
        <div className="col-md-4">
        <div className="card">
        <div className="card-body">
            {devCont}
            <br/>
            <DeviceForm/>
            <br/>
            <DeleteDeviceForm userID={user_id}/>      
        </div>
        </div>
        </div>
        <div className="col-md-4">
          <div className="card">
            <div className="card-body">
                {netCont}
                <br/>
                <AddNetworkForm/>
                <br/>
                <DeleteNetworkForm/>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
SettingsPage.propTypes = {
  user_id: PropTypes.string.isRequired
}
export default SettingsPage;
