
// This is for setting the route so that the website can calls and run functions that query the database
// This is so that the website won't runs the functions directly from the database
import Express from 'express'
import queryMongoDatabase from '../server/mongoControllers.js'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
import { connectToMongo } from './mongoControllers.js';
import { MongoClient, ServerApiVersion} from 'mongodb'

const username = 'user_test';
const password ='CZ66ttLSf5s0GVe4';

// Construct the MongoDB connection URI
const uri = "mongodb+srv://" + username + ":" + password + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority";

// Create a new client and connect to the server
const client = new MongoClient(uri);

dotenv.config()

const salt = 10
//login function
export async function login2(req, res) { 
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
    const scanIDs = []
    const networkIDs = []
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

      const insertDoc = await db.collection('User').insertOne({ username, password: hashPass, userID: user_id, scanIDs, networkIDs})
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

  //For cleaning is_exploit field
  /*
  async function updateVul(req, res){
    queryMongoDatabase(async db => {
      const response = await db.collection('Vulnerabilities').updateMany({}, {$unset: {"is_exploit": ""}})
      
      if (response){
        res.status(200).json({error: false, message: "success"})
      } else {
        res.status(404).json({error: true, message:"failed"})
      }
    }, 'ThreatSculpt')
  }
  */
   //FOR SHOWING ALL SCAN OF ONE USER
   async function findScanByUser (req, res) {
    const user_id = req.params.userID 
    queryMongoDatabase(async db => {
      const results = await db.collection('ScanResults').find({ userID: user_id }).toArray()
      if (results.length === 0) {
        res.status(404).json({ error: true, message: 'Scan not found' });
      } else {
        res.json(results);
      }
    }, 'ThreatSculpt')
  }

  async function findScanByNetwork (req, res) {
    const net_id = req.params.networkID 
    queryMongoDatabase(async db => {
      const results = await db.collection('ScanResults').find({ networkID: net_id }).toArray()
      if (results.length === 0) {
        res.status(404).json({ error: true, message: 'Scan not found' });
      } else {
        res.json(results);
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

  //CHECK WITH POSTMAN
  async function deleteAcc(req, res){
    const username = req.body.username
    const password = req.body.password

    queryMongoDatabase(async db => {
      const confirmUser = await db.collection('User').findOne({username})
      const userID = confirmUser.userID
      if (confirmUser < 1) { res.status(400).json({ error: true, message: 'Username or Password could not be found.' }) } else {
          const match = await bcrypt.compare(password, confirmUser.password)
          console.log(confirmUser.password)
          if (match.valueOf() === true) {
            //query to delete a user
            const deleteAcc = await db.collection('User').deleteOne({username})
            const deleteScans = await db.collection('ScanResults').deleteMany({userID: userID})
            const deleteNetworks = await db.collection('Networks').deleteMany({userID: userID})
            const deleteDevices = await db.collection('Devices').deleteMany({user_id: userID})
        
            if (deleteAcc && deleteDevices && deleteNetworks && deleteScans){
              res.status(200).json({error: false, message: 'Successfully delete the account'})
            } else {
              let message = 'Something went wrong in the database!'
              if (!deleteAcc) {
                message += ' Account Delete Failed!'
              }
              if (!deleteDevices) {
                message += ' Device Delete Failed!'
              }
              if (!deleteScans) {
                message += ' Scan Delete Failed!'
              }
              if (!deleteNetworks) {
                message += ' Network Delete Failed!'
              }
              res.status(400).json({error: true, message})
            }
          } else {
            res.status(404).json({ error: true, message: 'Username or Password could not be found. Deletion failed' })
          }
        }
      }, 'ThreatSculpt')
  }

  //TODO Postman check
  async function deleteNet(req, res){
    const host = req.body.host
    const name = req.body.name

    queryMongoDatabase(async db => {
      const confirmNet = await db.collection('Networks').findOne({host: host, name: name})
      if (confirmNet < 1) { res.status(400).json({ error: true, message: 'Network could not be found.' }) } else {
            const networkID = confirmNet.networkID
            //query to delete a user
            const deleteNet = await db.collection('Network').deleteOne({networkID})
            const deleteScans = await db.collection('ScanResults').deleteMany({networkID: networkID})
            
            if (deleteNet && deleteScans){
              res.status(200).json({error: false, message: 'Successfully delete the account'})
            } else {
              let message = 'Something went wrong in the database!'
              if (!deleteNet) {
                message += ' Network Delete Failed!'
              }
              if (!deleteScans) {
                message += ' Scan Delete Failed!'
              }
              res.status(400).json({error: true, message})
            }
        }
      }, 'ThreatSculpt')
  }

  async function deleteDev(req, res) {
    const ip_add = req.body.ip_add

    queryMongoDatabase(async db => {
      const confirmDev = await db.collection('Devices').findOne({ip_add})
      if (confirmDev < 1) { res.status(400).json({ error: true, message: 'Device could not be found.' }) } else {
            //query to delete a user
            const dev_id = confirmDev.dev_id
      
            const deleteDev = await db.collection('Devices').deleteOne({dev_id})
            const deleteVuls = await db.collection('Vulnerabilities').deleteMany({device_ip: ip_add})
            
            if (deleteNet && deleteVuls){
              res.status(200).json({error: false, message: 'Successfully delete the account'})
            } else {
              let message = 'Something went wrong in the database!'
              if (!deleteDev) {
                message += ' Device Delete Failed!'
              }
              if (!deleteVuls) {
                message += ' Vulnerabilities Delete Failed!'
              }
              res.status(400).json({error: true, message})
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
  
  //Get List of network based on userID
  export async function getNetworkList(req, res) {
    const userID = req.body.userID
    //console.log(userID)
    const db = client.db('ThreatSculpt');
    const netsCollection = db.collection('Networks');
    const netResults = await netsCollection.find({userID: userID}).toArray();
    //console.log(netResults)
    return res.json(netResults)
  }
  //Get lists of devices
  export async function getDeviceList(req, res) {
    const userID = req.body.userID
    const db = client.db('ThreatSculpt');
    const devCollection = db.collection('Devices');
    const devResults = await devCollection.find({user_id: userID}).toArray();
    return res.json(devResults)
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

  //----------------------ADDING-----------------------------------
  //Add a new device - WORKING
  async function addDevice(req, res) {
    const ip_add = req.body.ip_add
    const dev_id = req.body.dev_id
    const user_id = req.body.user_id

    queryMongoDatabase(async db => {
      const findDev = await db.collection('Devices').findOne({ dev_id })
      if ((findDev) !== null) { // Return error if username already exists
        res.status(404).json({ error: true, message: 'Device Already Exists.' })
        return
      }
      const insertDoc = await db.collection('Devices').insertOne({ dev_id,  ip_add, user_id})
      if (insertDoc.insertedCount !== null) { 
            res.json({ error: false, message: `Devices Added Successfully` })
         } 
        else { 
            res.status(404).json({ error: true, message: 'Failed to insert device info!' }) 
        }
    }, 'ThreatSculpt')
  }

  //WORKING - Compare with add device
  async function addNetwork(req, res) {
    const networkID = req.body.networkID;
    const host = req.body.host;
    const userID = req.body.userID;
    const scanIDs = [];
    
    queryMongoDatabase(async db => {
      const findDev = await db.collection('Networks').findOne({ networkID });
      if (findDev !== null) { // Return error if networkID already exists
        res.status(404).json({ error: true, message: 'Network Already Exists.' });
        return;
      }
      // Insert the network into the Networks collection
      await db.collection('Networks').insertOne({ networkID, userID, host, scanIDs });
        // Update the user document in the User collection
        const updateUser = await db.collection('User').updateOne(
          { userID: userID },
          { $push: { networkIDs: networkID } }
        );
        
        if (updateUser !== null) {
          res.status(200).json({ error: false, message: 'Network Added Successfully' });
        } else {
          res.status(404).json({ error: true, message: 'Failed to update user with networkID' });
        }
      }
    , 'ThreatSculpt');
  }

//-----------------------------------------------------
const dataRouter = new Express.Router()
dataRouter.post('/login', (req, res) => {
    console.log('Request body:', req.body)
    login2(req, res)
}) 
dataRouter.post('/signup', signup)

//Searching
dataRouter.get('/find/:username', findUser)
dataRouter.get('/find/scan/user/:userID', findScanByUser)
dataRouter.get('/find/scan/network/:networkID', findScanByNetwork)
dataRouter.get('/scan/:scanID', findScan)

//filtering
dataRouter.get('/filter/:filter', filter)

//deleting
dataRouter.get(`/scan/delete/:scanID`, deleteScan)
dataRouter.post('/acc/delete', deleteAcc)
dataRouter.post('/network/delete', deleteNet)

//update UserInfo
dataRouter.post('/acc/name', changeName)
dataRouter.post('/acc/password', changePass)

//Adding info
dataRouter.post('/add/device', addDevice)
dataRouter.post('/add/network', addNetwork)

dataRouter.post('/networks', getNetworkList)
dataRouter.post('/devices', getDeviceList)
//Uncomment for cleaning database
//dataRouter.get('/update/vul', updateVul)
export default dataRouter 

//-------------------------------------------------------

// Function to handle user login
export async function login(username, password, userCollection) {
  try {
    const user = await userCollection.findOne({ username, password });
    if (user) {
      // If user is found, return an object with login status and user data
      return user;
    } else {
        // If user is not found or incorrect credentials, return null
        return null;
    }
  } catch (error) {
    console.error('Error authenticating user:', error);
    throw new Error('Internal server error');
  }
}

// Function to get user information
export async function getUserInfo(username) {
  try {
    const { db, userCollection } = await connectToMongo(); // Establish MongoDB connection
    const user = await userCollection.findOne({ username });
    //console.log('Fetched user information:', user);
    return user;
  } catch (error) {
    console.error('Error fetching user information:', error);
    throw new Error('Internal server error');
  }
}

// Function to fetch scan results by user ID
export async function getUserData(userID) {
  try {
    console.log('Received userID in getUserData:', userID);
    const { db, userScanCollection } = await connectToMongo();
    const scanResultsCursor = await userScanCollection.find({ userID });
    const scanResults = await scanResultsCursor.toArray();
    console.log('Fetched scan results dataServices:', scanResults);
    return scanResults;
  } catch (error) {
    console.error('Error fetching scan results:', error);
    throw new Error('Internal server error');
  }
}

// Function to fetch user ID by username
export async function getUserID(username) {
  try {
    const { db, userCollection } = await connectToMongo();
    const user = await userCollection.findOne({ username });
    console.log('Fetched user ID:', user.userID); 
    return user.userID;
  }
  catch (error) {
    console.error('Error fetching user ID:', error);
    throw new Error('Internal server error');
  }
}