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

  //Searching for scanID
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

  //Delete account
  export async function deleteAcc(username, password) {
    try {
      const response = await fetch('http://localhost:3000/server/acc/delete', {
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

  //Account setting
  export async function setName(username, password, newUsername) {
    try {
      const response = await fetch('http://localhost:3000/server/acc/name', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password, newUsername })
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

  export async function setPass(username, password, newPassword) {
    try {
      const response = await fetch('http://localhost:3000/server/acc/password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password, newPassword })
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
  //Filter scan
  export async function search(filter){
    try {
      const response = await fetch(`http://localhost:3000/server/filter/${filter}`)
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