export async function login (username, password) {
    try {
      const response = await fetch('http://localhost:3000/server/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      })
      console.log(username)
      console.log(password)
      if (response.status >= 400) {
        throw new Error(`Request failed with response code ${response.status}`)
      }
      return true
    } catch (err) {
      console.error('Failed to login')
      console.error(err)
      return false
    }
  }

  export async function find (name) {
    try {
      const response = await fetch(`http://localhost:3000/server/find/${name}`)
      if (response.status >= 400) {
        throw new Error(`Request failed with response code ${response.status}`)
      }
      return await response.json()
    } catch (err) {
      console.error('Failed to find')
      console.error(err)
      return false
    }
  }

  export async function scan (id) {
    try {
      const response = await fetch(`http://localhost:3000/server/scan/${id}`)
      if (response.status >= 400) {
        throw new Error(`Request failed with response code ${response.status}`)
      }
      return await response.json()
    } catch (err) {
      console.error('Failed to find')
      console.error(err)
      return false
    }
  }

  export async function signUp (username, password) {
    try {
      const response = await fetch('http://localhost:3000/server/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      })
      console.log(username)
      console.log(password)
      if (response.status >= 400) {
        throw new Error(`Request failed with response code ${response.status}`)
      }
      return true
    } catch (err) {
      console.error('Failed to signup')
      console.error(err)
      return false
    }
  }

  export async function getAllScans(username) {
    try {
      const response = await fetch(`http://localhost:3000/server/getAllScans/${username}`);
      if (response.status >= 400) {
        throw new Error(`Request failed with response code ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      console.error('Failed to get all scans');
      console.error(err);
      return false;
    }
  }  