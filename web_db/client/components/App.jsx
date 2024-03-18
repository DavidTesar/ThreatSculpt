import React, { useState, useEffect } from 'react';
import { login, find, signUp, scan } from '../dataHelper';
import { Card, Button } from 'react-bootstrap';
function App() {
  // State to manage whether results are available
  const [resultsAvailable, setResultsAvailable] = useState(false);
  const [name, setName] = useState('')
  const [pass, setPass] = useState('')
  const [type, setType] = React.useState('password')
  const handleSubmit = async e => {
    e.preventDefault()
    try {
      const attemptLogin = await login(name, pass)
      if (attemptLogin) {
       console.log("Log in Successfully")
      } else {
        console.log("Failed to log in")
      }
    } catch (error) {
      console.log(error)
    }
  }

  const handleSignUp = async e => {
    e.preventDefault()
    try {
      const attemptSignUp = await signUp(name, pass)
      if (attemptSignUp) {
       console.log("Sign Up Successfully")
      } else {
        console.log("Failed to Sign Up")
      }
    } catch (error) {
      console.log(error)
    }
  }

  const handleFind = async e => {
    e.preventDefault()
    try {
      const attemptFind = await find(name)
      if (attemptFind) {
       console.log("Find Successfully")
       console.log(attemptFind)
      } else {
        console.log("Couldn't find user")
      }
    } catch (error) {
      console.log(error)
    }
  }

  const handleScan = async e => {
    e.preventDefault()
    try {
      const attemptScan = await scan(name)
      if (attemptScan) {
       console.log("Found Scan Result Successfully")
       console.log(attemptScan)
      } else {
        console.log("Couldn't find scan id")
      }
    } catch (error) {
      console.log(error)
    }
  }
  useEffect(() => {
    // Simulate fetching data or checking for results
    setTimeout(() => {
      setResultsAvailable(true);
    }, 8000); // Simulate a delay of 3 seconds
  }, []);

  return (
    <div>
      <Card style={{ width: '18rem' }} className="mx-auto mt-5">
      <Card.Body>
        <form method = 'post' onSubmit={handleSubmit}>
      <label>
        {'Please enter your information to log in.'}
      </label>
      <br/>
      <label>
      {'Username: '}
      <input
        name="username"
        value={name}
        onChange={e => setName(e.target.value)}
      />
      </label>
      <label>
      {'Password: '}
      <input
        type = {type}
        name="password"
        value={pass}
        onChange={e => setPass(e.target.value)}
      />
      </label>
      <label>
        <Button variant='outline' type = 'submit' className =  'mt-3 center' >Log In</Button>
      </label>
      </form>
      <div className = 'mt-3'>
      </div>
      </Card.Body>
    </Card>
    <br/>
    <Card style={{ width: '18rem' }} className="mx-auto mt-5">
      <Card.Body>
        <form method = 'get' onSubmit={handleFind}>
      <br/>
      <label>
      {'Username: '}
      <input
        name="username"
        value={name}
        onChange={e => setName(e.target.value)}
      />
      </label>
      <label>
        <Button variant='outline' type = 'submit' className =  'mt-3 center' >Find</Button>
      </label>
      </form>
      <div className = 'mt-3'>
      </div>
      </Card.Body>
    </Card>
    <br/>
    <Card style={{ width: '18rem' }} className="mx-auto mt-5">
      <Card.Body>
        <form method = 'post' onSubmit={handleSignUp}>
      <br/>
      <label>
      {'Username: '}
      <input
        name="username"
        value={name}
        onChange={e => setName(e.target.value)}
      />
      </label>
      <label>
      {'Password: '}
      <input
        type = {type}
        name="password"
        value={pass}
        onChange={e => setPass(e.target.value)}
      />
      </label>
      <label>
        <Button variant='outline' type = 'submit' className =  'mt-3 center' >Sign Up</Button>
      </label>
      </form>
      <div className = 'mt-3'>
      </div>
      </Card.Body>
      </Card>
      <br/>
      <Card style={{ width: '18rem' }} className="mx-auto mt-5">
      <Card.Body>
        <form method = 'get' onSubmit={handleScan}>
      <br/>
      <label>
      {'Scan ID: '}
      <input
        name="username"
        value={name}
        onChange={e => setName(e.target.value)}
      />
      </label>
      <label>
        <Button variant='outline' type = 'submit' className =  'mt-3 center' >Find</Button>
      </label>
      </form>
      <div className = 'mt-3'>
      </div>
      </Card.Body>
    </Card>
  </div>

  );
}

export default App;