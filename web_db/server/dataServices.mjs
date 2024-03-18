import queryMongoDatabase from './mongoControllers.js'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
dotenv.config()

//login function
export async function logIn(req, res) { 
    const username = req.body.username
    const password = req.body.password
    console.log(username)
    console.log(password)
    queryMongoDatabase(async db => {
        const loginSuccess = await db.collection('User').findOne({username})
        if (loginSuccess < 1) { res.status(400).json({ error: true, message: 'Username or Password could not be found.' }) } else {
            const match = await bcrypt.compare(password, loginSuccess.password)
            if (match.valueOf() === true) {
              if (req.body.username === username) {
                res.json({ error: true, message: `User: ${username} Already Logged In Successfully` })
              } else {
                req.body.username = username
              }
            } else {
              res.status(401).json({ error: true, message: 'Username or Password could not be found.' })
            }
          }
        }, 'ThreatSculpt')
  }

