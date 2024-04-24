import express from 'express';
import bodyParser from 'body-parser';
import { MongoClient } from 'mongodb';
import cors from 'cors';
import { spawn } from 'child_process';

const app = express();
let port = process.env.PORT || 4000; 

const username = 'user_test';
const password = 'CZ66ttLSf5s0GVe4';
const uri = `mongodb+srv://${username}:${password}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority`;

let usersCollection;
// Initialize an array to store scan IDs
let storedScanIDs = [];
// Initialize storedScanIDs as an empty array
storedScanIDs = [];

let userCollection;
let userScanCollection; // Define userScanCollection for /getUserData endpoint

const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectToMongo() {
  try {
    await client.connect();
    const db = client.db('ThreatSculpt');
    userCollection = db.collection('User');
    userScanCollection = db.collection('ScanResults'); // Initialize userScanCollection
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
  }
}

app.use(bodyParser.json());
app.use(cors());

//-----------------------------------------------------------------------------------------------------------


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await userCollection.findOne({ username, password });
    if (user) {
      // Store the username in req.user
      req.user = { username };
      
      console.log('req.user:', req.user); // Log the stored username
      console.log('Login username:', username); // Log the fetched user
      // Send success response with username
      res.status(200).json({ username });
      console.log('Sent username:', username); // Log the sent username
      console.log(`[start-server] Successful login for username: '${username}'`);
      // Trigger the '/get-scan-ids' route handler immediately after successful login
      await getScanIDs(username);

      
    } else {
      // User not found or incorrect credentials, send error response
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Error authenticating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/getUserInfo', async (req, res) => {
  const { username } = req.body;

  console.log('Received username:', username); // Log the received username
  
  try {
    const userInfo = await userCollection.findOne({ username });
    if (userInfo) {
      res.status(200).json(userInfo);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error fetching user information:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/getUserData', async (req, res) => {
  const { userID } = req.body;

  //console.log('req.body userID:', req); // Log the received request body (userID
  console.log('Received userID:', userID); // Log the received userID
  console.log('userScanCollection:', userScanCollection); // Log the userScanCollection (ScanResults collection

  try {
    const scanResults = await userScanCollection.find({ userID }).toArray();
    console.log('Fetched scan results:', scanResults); // Log the fetched scan results
    res.status(200).json(scanResults);
  } catch (error) {
    console.error('Error fetching scan results:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Server side for getting user ID by username
app.post('/getUserID', async (req, res) => {
  const { username } = req.body;

  try {
    const user = await userCollection.findOne({ username });
    console.log('Fetched user ID:', user.userID); // Log the fetched user ID
    const userID = user.userID;
    console.log('Checking before sending user ID:', userID); // Log the sent user ID
    res.status(200).json({ userID });
    console.log('Sent user ID:', userID); // Log the sent user ID
  } catch (error) {
    console.error('Error fetching user ID:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//-----------------------------------------------------------------------------------------------------

app.post('/nmap', async (req, res) => {
  const { scanType } = req.body;
  console.log("Received scanType:", scanType);
  
  // Map scanType to complexity
  let complexity;
  switch (scanType) {
    case 'simple':
      complexity = 'simple';
      break;
    case 'classic':
      complexity = 'classic';
      break;
    case 'advanced':
      complexity = 'advanced';
      break;
    default:
      console.error('Invalid scanType:', scanType);
      res.status(400).json({ error: 'Invalid scanType' });
      return;
  }

  console.log("Using complexity:", complexity);

  try {
    // Perform Nmap scan with the corresponding complexity level
    const result = await performNmapScan('localhost', complexity);
    
    // Send the result as response
    res.status(200).json(result);
  } catch (error) {
    console.error('Error performing Nmap scan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function performNmapScan(subnet, complexity) {
  try {
    console.log("Performing Nmap scan with subnet:", subnet, "and complexity:", complexity);

    // Execute the Python script using child_process.spawn
    const pythonProcess = spawn('python', ['scanin.py', subnet, complexity]);

    let result = '';

    // Capture the output of the Python script
    pythonProcess.stdout.on('data', (data) => {
      result += data.toString();
    });

    // Handle any errors that occur during the execution
    pythonProcess.on('error', (err) => {
      console.error('Error executing Python script:', err);
      throw err;
    });

    // Wait for the Python script to finish executing
    await new Promise((resolve, reject) => {
      pythonProcess.on('close', (code) => {
        if (code === 0) {
          console.log("Nmap scan completed successfully");
          resolve();
        } else {
          reject(new Error(`Python script exited with code ${code}`));
        }
      });
    });

    return result;
  } catch (error) {
    console.error('Error performing Nmap scan:', error);
    throw error; 
  }
}

//---------------------------------------------------------------------------------------------------

async function getScanIDs(username) {
  try {
      // Execute the ScanPrinter.py script to get scan IDs
      const pythonProcess = spawn('python', ['ScanPrinter.py', username]);

      let scanIDs = '';

      // Capture the output of the Python script
      pythonProcess.stdout.on('data', (data) => {
          scanIDs += data.toString();
      });

      // Handle any errors that occur during the execution
      pythonProcess.on('error', (err) => {
          console.error('Error executing Python script:', err);
          // Handle the error here, or log it
      });

      // Wait for the Python script to finish executing
      await new Promise((resolve, reject) => {
          pythonProcess.on('close', (code) => {
              if (code === 0) {
                  console.log("Scan IDs retrieved successfully");
                  // Store the scan IDs
                  storedScanIDs = scanIDs.split('\n').filter(id => id.trim() !== ''); // Assuming each ID is on a new line
                  resolve(); // Resolve when scan IDs are stored
              } else {
                  reject(new Error(`Python script exited with code ${code}`));
              }
          });
      });
  } catch (error) {
      console.error('Error getting scan IDs:', error);
      throw error; // Throw error to be caught in the catch block
  }
}

// Call the function to retrieve scan IDs during server startup
getScanIDs().catch(error => console.error('Error initializing scan IDs:', error));

// Endpoint to retrieve stored scan IDs
app.get('/fetch-scan-ids', (_req, res) => {
  // Return stored scan IDs
  res.status(200).json({ scanIDs: storedScanIDs });
});
//-----------------------------------------------------------------------------------------------------------------------

// Start the server and connect to MongoDB
const server = app.listen(port, async () => {
  await connectToMongo();
  console.log(`Server is running on port ${server.address().port}`);
});