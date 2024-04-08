
// This is for setting the route so that the website can calls and run functions that query the database
// This is so that the website won't runs the functions directly from the database
import Express from 'express'
import queryMongoDatabase from '../server/mongoControllers.js'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
dotenv.config()
const salt = 10
//login function
export async function login(req, res) { 
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
    const user_id = req.body.user_id
    let is_hashed = true
    const hashPass = await bcrypt.genSalt(salt).then(this_salt => {
      if (password !== null && this_salt !== null) {  
        return bcrypt.hash(password, this_salt)
      } else {
        is_hashed = false
        return
      }
    })
    if (!is_hashed){
      res.status(404).json({ error: true, message: 'Error in hashing password' })
      return
    }
    queryMongoDatabase(async db => {
      const signupSuccess = await db.collection('User').findOne({ username })
      if ((signupSuccess) !== null) { // Return error if username already exists
        res.status(404).json({ error: true, message: 'Username Already Exists.' })
        return
      }

      const insertDoc = await db.collection('User').insertOne({ username, password: hashPass, user_id})
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

  async function deleteAcc(req, res){
    const username = req.body.username
    const password = req.body.password

    queryMongoDatabase(async db => {
      const confirmUser = await db.collection('User').findOne({username})
      if (confirmUser < 1) { res.status(400).json({ error: true, message: 'Username or Password could not be found.' }) } else {
          const match = await bcrypt.compare(password, confirmUser.password)
          console.log(confirmUser.password)
          if (match.valueOf() === true) {
            //query to delete a user
            const deleteAcc = await db.collection('User').deleteOne({username})
            if (deleteAcc){
              res.status(200).json({error: false, message: 'Successfully delete the account'})
            } else {
              res.status(404).json({error: true, message: 'Could not delete Account'})
            }
          } else {
            res.status(401).json({ error: true, message: 'Username or Password could not be found. Deletion failed' })
          }
        }
      }, 'ThreatSculpt')
  }

  async function deleteScan(req, res){
    const scanID = req.params.scanID

    queryMongoDatabase(async db => {
      const confirmScan = await db.collection('ScanResults').findOne({scanID})
      if (confirmScan < 1) { res.status(400).json({ error: true, message: 'ScanID could not be found.' }) } else {
            const deleteScan = await db.collection('ScanResults').deleteOne({scanID})
            if (deleteScan) {
              res.status(200).json({error: false, message: 'Delete successfully'})
            } else {
              res.status(404).json({error: true, message: 'Could not delete scan for some reasons'})
            }
          }
      }, 'ThreatSculpt')
  }

  async function filter(req, res){
    const filter = req.params.filter
    if (filter === 'This Month') {
      var today = new Date(); // Date and time to start filtering
      var endDate = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate()); // Date and time to end filtering
    }
    else if (filter === 'This Week'){
      var today = new Date(); // Date and time to start filtering
      var endDate = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 7); // Date and time to end filtering
    }
    else if (filter === 'Last Month'){
      var today = new Date(); // Date and time to start filtering
      var endDate = new Date(today.getFullYear(), today.getMonth() - 2, today.getDate());
      today = new Date(today.getFullYear(), today.getMonth() -1, today.getDate())
    }
    queryMongoDatabase(async db => {
      const findResult = await db.collection('ScanResults').find({
        "date": { 
          $gte: today, 
          $lte: endDate
      }})
      //THIS MIGHT NOT WORK PROPERLY
      if (findResult.toArray().length < 0) {
        res.status(404).json({error: true, message: 'Could not find any result in this range of date'})
      } else {
        res.json(findResult)
      }
    }, 'ThreatSculpt')
  }

  export async function getScanResults() {
    // Logic to retrieve scan results from the database
    // For example, using a MongoDB collection:
    const db = client.db('ThreatSculpt');
    const scansCollection = db.collection('ScanResults');
    const scanResults = await scansCollection.find({}).toArray();
    return scanResults;
  }
  

  async function changeName(req, res) {
    const username = req.body.username
    const password = req.body.password
    const newUsername = req.body.newUsername

    queryMongoDatabase(async db => {
        const loginSuccess = await db.collection('User').findOne({username})
        if (loginSuccess < 1) { res.status(400).json({ error: true, message: 'Username or Password could not be found.' }) } else {
            const match = await bcrypt.compare(password, loginSuccess.password)
            console.log(loginSuccess.password)
            if (match.valueOf() === true) {
              //Change account name
              changeName = await db.collection('User')
                .updateOne({username: username}, {username: newUsername})
              if (changeName) {
                res.status(200).json({error: false, message: 'Successfully change name'})
              } else {
                res.status(404).json({error: true, message: 'Could not change user name'})
              }
            } else {
              res.status(401).json({ error: true, message: 'Username or Password could not be found.' })
            }
          }
        }, 'ThreatSculpt')
  }

  async function changePass(req, res) {
    const username = req.body.username
    const password = req.body.password
    const newPassword = req.body.newPassword

    queryMongoDatabase(async db => {
        const loginSuccess = await db.collection('User').findOne({username})
        if (loginSuccess < 1) { res.status(400).json({ error: true, message: 'Username or Password could not be found.' }) } else {
            const match = await bcrypt.compare(password, loginSuccess.password)
            console.log(loginSuccess.password)
            if (match.valueOf() === true) {
              changePass = await db.collection('User')
                .updateOne({password: password}, {password: newPassword})
              if (changePass) {
                res.status(200).json({error: false, message: 'Successfully change name'})
              } else {
                res.status(404).json({error: true, message: 'Could not change user name'})
              }
            } else {
              res.status(401).json({ error: true, message: 'Username or Password could not be found.' })
            }
          }
        }, 'ThreatSculpt')
  }

  async function addDevice(req, res) {
    const type = req.body.type
    const name = req.body.name
    const id = req.body.id
    const user_id = req.body.user_id

    queryMongoDatabase(async db => {
      const findDev = await db.collection('Devices').findOne({ id })
      if ((findDev) !== null) { // Return error if username already exists
        res.status(404).json({ error: true, message: 'Device Already Exists.' })
        return
      }
      const insertDoc = await db.collection('Devices').insertOne({ name, type, id, user_id})
      if (insertDoc.insertedCount !== null) { 
            res.json({ error: false, message: `Devices Added Successfully` })
         } 
        else { 
            res.status(404).json({ error: true, message: 'Failed to insert device info!' }) 
        }
    }, 'ThreatSculpt')
  }
//-----------------------------------------------------

const dataRouter = new Express.Router()
dataRouter.post('/login', (req, res) => {
    console.log('Request body:', req.body)
    login(req, res)
}) 
dataRouter.post('/signup', signup)
dataRouter.get('/find/:username', findUser)
//TODO: Check if works
dataRouter.get('/scan/:scanID', findScan)
dataRouter.get(`/scan/delete/:scanID`, deleteScan)
dataRouter.get('/filter/:filter', filter)
dataRouter.post('/acc/delete', deleteAcc)
dataRouter.post('/acc/name', changeName)
dataRouter.post('/acc/password', changePass)

dataRouter.post('/add/device', addDevice)

export default dataRouter 