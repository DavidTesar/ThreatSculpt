import express from 'express';
import bodyParser from 'body-parser';
import { MongoClient } from 'mongodb';
import cors from 'cors';

const app = express();
const port = process.env.PORT || 4000;

const username = 'user_test';
const password = 'CZ66ttLSf5s0GVe4';
const uri = `mongodb+srv://${username}:${password}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority`;

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

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await userCollection.findOne({ username, password });
    if (user) {
      res.status(200).json({ message: 'Login successful' });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Error authenticating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/getUserInfo', async (req, res) => {
  const { username } = req.body;

  //console.log('req.body username:', req); // Log the received request body (username)
  //console.log('Received username:', username); // Log the received username
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
  //console.log('Received userID:', userID); // Log the received userID
  try {
    const scanResults = await userScanCollection.find({ userID }).toArray();
    //console.log('Fetched scan results:', scanResults); // Log the fetched scan results
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
    //console.log('Fetched user ID:', user.userID); // Log the fetched user ID
    const userID = user.userID;
    //console.log('Checking before sending user ID:', userID); // Log the sent user ID
    res.status(200).json({ userID });
    //console.log('Sent user ID:', userID); // Log the sent user ID
  } catch (error) {
    console.error('Error fetching user ID:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server and connect to MongoDB
const server = app.listen(port, async () => {
  await connectToMongo();
  console.log(`Server is running on port ${server.address().port}`);
});
