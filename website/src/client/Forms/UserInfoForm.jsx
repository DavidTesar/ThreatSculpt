import { useState } from "react";
import { useNavigate } from "react-router-dom";
import PropTypes from 'prop-types'
export default function UserInfoForm(props) {
  const { setIsLoggedIn } = props
  // State for user info form
  const [userInfo, setUserInfo] = useState({
    name: '',
    newName: '',
    password: '',
    newPassword: '',
    changeName: false,
    changePassword: false
  });
  const navigate = useNavigate()
  // Handler for changing user info form
  const handleUserInfoChange = (e) => {
    const { name, value, type, checked } = e.target;
    if (name === "changeName" && checked) {
      setUserInfo(prevState => ({
        ...prevState,
        changeName: true,
        changePassword: false
      }));
    } else if (name === "changePassword" && checked) {
      setUserInfo(prevState => ({
        ...prevState,
        changeName: false,
        changePassword: true
      }));
    } else {
      setUserInfo(prevState => ({
        ...prevState,
        [name]: type === 'checkbox' ? checked : value
      }));
    }
  };

  const handleSubmitUserInfo =async (e) => {
    e.preventDefault();
    if (userInfo.changeName) {
      const response = await fetch('http://localhost:4000/server/acc/name', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: userInfo.name,
          newUsername: userInfo.newName,
          password: userInfo.password,
        }),
      })
        if (response.ok){
          alert('Name changed successfully!');
          setUserInfo((prevState) => ({
            ...prevState,
            name: userInfo.newName
          }));
      } else {
        // Show an error message if there is an issue adding the network
        alert('Error: Failed to change name');
      }
    }
    if (userInfo.changePassword) {
      const response2 = await fetch('http://localhost:4000/server/acc/password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: userInfo.name,
          password: userInfo.password,
          newPassword: userInfo.newPassword,
        }),
      })
      if (response2.ok){
        alert('Password changed successfully!');
        setUserInfo((prevState) => ({
          ...prevState,
          password: userInfo.newPassword
        }));
      } else {
        // Show an error message if there is an issue adding the network
        alert('Error: Failed to change password');
      }
    }
  };

  const handleDelete = async (e) => {
    e.preventDefault();
    const response2 = await fetch('http://localhost:4000/server/acc/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: userInfo.name,
          password: userInfo.password,
        }),
      })
      if (response2.ok){
        alert('Account is deleted');
        setUserInfo((prevState) => ({
          ...prevState,
          name: '',
          newName: '',
          password: '',
          newPassword: '',
          changeName: false,
          changePassword: false
        }));
        navigate('/signup')
        setIsLoggedIn(false)
      } else {
        // Show an error message if there is an issue adding the network
        alert('Error: Failed to delete account');
      }
  }

  return (
    <div>
      <div className="card">
        <div className="card-body">
          <h5 className="card-title">Change User Info</h5>
          <form onSubmit={handleSubmitUserInfo}>
            <div className="form-group">
              <label htmlFor="name">Name</label>
              <input
                type="text"
                className="form-control"
                id="name"
                name="name"
                value={userInfo.name}
                onChange={handleUserInfoChange}
              />
            </div>
            <div className="form-group form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="changeName"
                name="changeName"
                checked={userInfo.changeName}
                onChange={handleUserInfoChange}
              />
              <label className="form-check-label" htmlFor="changeName">Change Name</label>
            </div>
            <div className="form-group">
              <label htmlFor="newName">New Name</label>
              <input
                type="text"
                className="form-control"
                id="newName"
                name="newName"
                value={userInfo.newName}
                onChange={handleUserInfoChange}
                disabled={!userInfo.changeName}
              />
            </div>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                type="password"
                className="form-control"
                id="password"
                name="password"
                value={userInfo.password}
                onChange={handleUserInfoChange}
              />
            </div>
            <div className="form-group form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="changePassword"
                name="changePassword"
                checked={userInfo.changePassword}
                onChange={handleUserInfoChange}
              />
              <label className="form-check-label" htmlFor="changePassword">Change Password</label>
            </div>
            <div className="form-group">
              <label htmlFor="newPassword">New Password</label>
              <input
                type="password"
                className="form-control"
                id="newPassword"
                name="newPassword"
                value={userInfo.newPassword}
                onChange={handleUserInfoChange}
                disabled={!userInfo.changePassword}
              />
            </div>
            <button type="submit" className="btn btn-primary">Save Changes</button>
          </form>
        </div>
      </div>
      <div className="card">
        <div className="card-header">Delete Account</div>
        <div className="card-body">
          <form onSubmit={handleDelete}>
            <div className="form-group">
              <label htmlFor="name">Name</label>
              <input
                type="text"
                className="form-control"
                id="name"
                name="name"
                value={userInfo.name}
                onChange={handleUserInfoChange}
              />
            </div>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                type="password"
                className="form-control"
                id="password"
                name="password"
                value={userInfo.password}
                onChange={handleUserInfoChange}
              />
            </div>
            <button type="submit" className="btn btn-danger">Delete Account</button>
          </form>
        </div>
      </div>
    </div>
  );
}
UserInfoForm.propTypes = {
  setIsLoggedIn: PropTypes.func
};