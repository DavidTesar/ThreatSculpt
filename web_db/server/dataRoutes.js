// This is for setting the route so that the website can calls and run functions that query the database
// This is so that the website won't runs the functions directly from the database
import Express from 'express'
import queryMongoDatabase from './mongoControllers.js'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
dotenv.config()
const salt = 10
//login function
async function logIn(req, res) { 
    const username = req.body.username
    const password = req.body.password
    queryMongoDatabase(async db => {
        const loginSuccess = await db.collection('User').findOne({username})
        if (loginSuccess < 1) { res.status(400).json({ error: true, message: 'Username or Password could not be found.' }) } else {
            const match = await bcrypt.compare(password, loginSuccess.password)
            console.log(loginSuccess.password)
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

async function signup (req, res) { // working without authentication ------------------TO DO --------------------
    const username = req.body.username
    const password = req.body.password
    
    const hashPass = await bcrypt.genSalt(salt).then(salt => {
        return bcrypt.hash(password, salt)
    })
    console.log(hashPass)
    queryMongoDatabase(async db => {
      const signupSuccess = await db.collection('User').findOne({ username })
      if ((signupSuccess) !== null) { // Return error if username already exists
        res.status(404).json({ error: true, message: 'Username Already Exists.' })
        return
      }

      const insertDoc = await db.collection('User').insertOne({ username, password: hashPass})
      if (insertDoc.insertedCount !== null) { 
            res.json({ error: false, message: `User: ${username} Signed Up Successfully` })
         } 
        else { 
            res.status(404).json({ error: true, message: 'Failed to insert user info!' }) 
        }
    }, 'ThreatSculpt')
  }


async function findUser (req, res) {
    const username = req.params.username // eventually change to session
    queryMongoDatabase(async db => {
      const findAccount = await db.collection('User').find({ username })
      const numDocs = await db.collection('User').countDocuments({ username })
  
      if (numDocs === 0) { // check if no user / duplicate users
        res.status(404).json({ error: true, message: 'User not found' })
      } else if (numDocs > 1) {
        res.status(500).json({ error: true, message: 'Multiple users with same username' })
      } else {
        for await (const doc of findAccount) {
          res.json(doc)
        }
      }
    }, 'ThreatSculpt')
  }


  async function findScan (req, res) {
    const scanID = req.params.scanID // eventually change to session
    queryMongoDatabase(async db => {
      const findScan = await db.collection('ScanResults').find({ scanID })
      const numDocs = await db.collection('ScanResults').countDocuments({ scanID })
  
      if (numDocs === 0) { // check if no user / duplicate users
        res.status(404).json({ error: true, message: 'Scan not found' })
      } else if (numDocs > 1) {
        res.status(500).json({ error: true, message: 'Multiple scan results with same ID' })
      } else {
        for await (const doc of findScan) {
          res.json(doc)
        }
      }
    }, 'ThreatSculpt')
  }
//-----------------------------------------------------

const dataRouter = new Express.Router()
dataRouter.post('/login', (req, res) => {
    console.log('Request body:', req.body)
    logIn(req, res)
}) 
dataRouter.post('/signup', signup)
dataRouter.get('/find/:username', findUser)
dataRouter.get('/scan/:scanID', findScan)
// Make the router available to import in other files
export default dataRouter 