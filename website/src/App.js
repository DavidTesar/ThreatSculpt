//NOTICE: to turn off bcrypt just change fetch for login into localhost:4000/login instead of /server/login
//Make sure you change back to /server/login afterward for security reason - Thank you
import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types'
import './App.css';
import './assets/bootstrap/css/bootstrap.min.css';
import './assets/fonts/fontawesome-all.min.css';
import './assets/css/bs-theme-overrides.css';
import logo from './assets/img/logo.png';
import {useNavigate} from 'react-router-dom'
import Navigation from './client/Navigation.jsx';
import {Routes, Route, Switch, BrowserRouter as Router, uselocation} from 'react-router-dom';
import SignUp from './SignUp.js';
import SearchPage from './client/Search.jsx';
import DeviceForm from './client/Forms/AddDeviceForm.jsx';
import Dashboard from './client/Dashboard.jsx';
import SettingsPage from './client/Setting.jsx';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [userID, setUserID] = useState('')
  const [loggingIn, setLoggingIn] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userInfo, setUserInfo] = useState(null);
  const [scanResults, setScanResults] = useState([]);

  const handleLogin = async () => {
    setLoggingIn(true);
    try {
      const response = await fetch('http://localhost:4000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      if (response.ok) {
        // Login successful
        setLoginError('');
        setIsLoggedIn(true);
      } else {
        // Login failed
        const errorData = await response.json();
        setLoginError(errorData.error);
      }
    } catch (error) {
      console.error('Network error:', error);
      setLoginError('Network error. Please try again later.');
    }
    setLoggingIn(false);
  };

  useEffect(() => {
    // Automatically login when component mounts
    handleLogin();
  }, []); // Empty dependency array ensures it only runs once on mount

  const fetchID = async () => {
    try {
      const response = await fetch(`http://localhost:4000/server/find/${username}`);
      if (response.ok) {
        const data = await response.json()
        setUserID(data.userID)
      } else {
        console.log("failed to get ID")
      }
    } catch (error) {
      console.error('Network error:', error);
    }
  }

  //get ID for the setting page
  useEffect(() => {
    fetchID();
  }, []);

  console.log("User ID:" + userID)

  return (
    <Router>    
    <Navigation isLoggedIn = {isLoggedIn} setIsLoggedIn={setIsLoggedIn}></Navigation>
    <Routes>
    <Route path="/" element={<Dashboard username={username}/> }/>
    <Route
            path="/login"
            exact
            element={
              <LogIn username={username} setUsername={setUsername} password={password}
              setIsLoggedIn={setIsLoggedIn} setLoggingIn={setLoggingIn} setLoginError={setLoginError}
              setPassword={setPassword} loggingIn={loggingIn} loginError={loginError} isLoggedIn={isLoggedIn}
        ></LogIn>
            }
          />
          <Route
            path="/signup"
            element= {<SignUp username={username} setUsername={setUsername} password={password}
            setIsLoggedIn={setIsLoggedIn} setLoggingIn={setLoggingIn} setLoginError={setLoginError}
            setPassword={setPassword} loggingIn={loggingIn} loginError={loginError} isLoggedIn={isLoggedIn} />}
          />
          <Route
            path = "/search"
            element = {<SearchPage userID={userID}></SearchPage>}
          />
           <Route
            path = "/setting"
            element = {<SettingsPage user_id={userID} setIsLoggedIn={setIsLoggedIn}></SettingsPage>}
          />
          <Route
            path = "/logout"
          />
    </Routes>
    </Router>
  );
}

function LogIn(props) {
  const { username, password, loggingIn, loginError, isLoggedIn
        , setIsLoggedIn, setLoggingIn, setLoginError, setPassword, setUsername
  } = props
  const navigate = useNavigate()
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoggingIn(true);
    try {
      const response = await fetch('http://localhost:4000/server/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      console.log('Login before ok response', response)
      if (response.ok) {
        console.log('Login after ok response', response)
        // Login successful
        setLoginError('');
        setIsLoggedIn(true);
        navigate('/')
      } else {
        // Login failed
        const errorData = await response.json();
        setLoginError(errorData.error);
      }
    } catch (error) {
      console.error('Network error:', error);
      setLoginError('Network error. Please try again later.');
    }
    setLoggingIn(false);
  };

  return (
  <body class="bg-gradient-primary">
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-9 col-lg-12 col-xl-10">
          <div class="card shadow-lg o-hidden border-0 my-5">
            <div class="card-body p-0">
          
          <div className="login-container" class="p-5">
            <div class="text-center">
              <h2>{isLoggedIn ? `Welcome, ${username}!` : 'Login'}</h2>
            </div>
            {!isLoggedIn && (
              <div class="row">
              <div className="col-lg-6 d-none d-lg-flex">
                <div 
                  className="flex-grow-1 bg-login-image" 
                      style={{
                      backgroundImage: `url(${logo})`,
                        backgroundSize: 'contain', // Ensures the image fits without being cut off
                        backgroundRepeat: 'no-repeat', // Prevents the image from repeating
                        backgroundPosition: 'center' // Centers the background image in the container
                    }}>
                </div>
              </div>
              
              <div class="col-lg-6">
              <form onSubmit={handleLogin}>
                  <div class="mb-3">
                    <label htmlFor="username">Username:</label>
                      <input
                        type="text"
                        id="username"
                        class = "form-control form-control-user"
                        placeholder = "Enter username..."
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                      />
                  </div>
                <div class="mb-3">
                  <label htmlFor="password">Password:</label>
                  <input
                    type="password"
                    id="password"
                    class = "form-control form-control-user"
                    placeholder = "Enter password..."
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                <button 
                type="submit" 
                class = "btn btn-primary d-block btn-user w-100"
                disabled={loggingIn}>
                  {loggingIn ? 'Logging in...' : 'Login'}
                </button>
                <br/>
                <button  
                class = "btn btn-primary d-block btn-user w-100"
                onClick={ ()=>{ navigate('/signup')}}
                > Don't have an account?
                
                </button>
                {loginError && <div className="error-message">{loginError}</div>}
              </form>
              </div>
              </div>
            )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </body>
  );
}
LogIn.propTypes = {
  username: PropTypes.string,
  password: PropTypes.string,
  loggingIn: PropTypes.bool, 
  loginError: PropTypes.string,
  isLoggedIn: PropTypes.bool.isRequired, 
  setIsLoggedIn: PropTypes.func.isRequired, 
  setLoggingIn:PropTypes.func.isRequired, 
  setLoginError:PropTypes.func.isRequired, 
  setPassword:PropTypes.func.isRequired, 
  setUsername:PropTypes.func.isRequired
}
LogIn.defaultProps = {
  username: "",
  password: "",
  loggingIn: false, 
  loginError: ""
}
export default App;
