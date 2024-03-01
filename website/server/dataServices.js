import queryMongoDatabase from '../server/mongoControllers'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
dotenv.config()

//login function
export async function login(req, res) { 
    const username = req.body.username
    const password = req.body.password
    console.log(username)
    console.log(password)
    queryMongoDatabase(async db => {
        const loginSuccess = await db.collection('User').findOne({username})
        if (loginSuccess < 1) { res.status(404).json({ error: true, message: 'Username or Password could not be found.' }) } else {
            const match = await bcrypt.compare(password, loginSuccess.password)
            if (match.valueOf() === true) {
              if (req.body.username === username) {
                res.json({ error: true, message: `User: ${username} Already Logged In Successfully` })
              } else {
                req.body.username = username
              }
            } else {
              res.status(404).json({ error: true, message: 'Username or Password could not be found.' })
            }
          }
        }, 'ThreatSculpt')
  }
