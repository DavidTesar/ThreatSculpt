import { useState } from "react";

export default function UserInfoForm() {
  // State for user info form
  const [userInfo, setUserInfo] = useState({
    name: '',
    newName: '',
    password: '',
    newPassword: '',
    changeName: false,
    changePassword: false
  });

  // Handler for changing user info form
  const handleUserInfoChange = (e) => {
    const { name, value, type, checked } = e.target;
    setUserInfo((prevState) => ({
      ...prevState,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  // Handler for submitting user info form
  const handleSubmitUserInfo = (e) => {
    e.preventDefault();
    // Logic for submitting user info form data
    console.log('User info submitted:', userInfo);
  };

  const handleDelete = (e) => {
    e.preventDefault();
    console.log('Delete User: ' + userInfo.name + ' ' + userInfo.password);
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
