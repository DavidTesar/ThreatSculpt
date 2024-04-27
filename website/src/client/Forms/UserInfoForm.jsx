import { useState } from "react";

export default function UserInfoForm () {
      // State for user info form
  const [userInfo, setUserInfo] = useState({
    name: '',
    password: '',
    newpassword: ''
  });
  
  // Handler for changing user info form
  const handleUserInfoChange = (e) => {
    const { name, value } = e.target;
    setUserInfo((prevState) => ({
      ...prevState,
      [name]: value,
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
    console.log('Delete User: ' + userInfo.name + ' ' + userInfo.password)
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
                <div className="form-group">
                  <label htmlFor="newPassword">New Password</label>
                  <input
                    type="password"
                    className="form-control"
                    id="newpassword"
                    name="newpassword"
                    value={userInfo.newpassword}
                    onChange={handleUserInfoChange}
                  />
                </div>
                <button type="submit" className="btn btn-primary">Save Changes</button>
              </form>
            </div>
          </div>
          <div className="card">
            <div className="card-header">Delete Account </div>
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
                <button type="submit" className="btn btn-danger"> Delete Account </button>
          </form>
           </div>
          </div>
          </div>
    )
}