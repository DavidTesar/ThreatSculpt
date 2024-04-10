import express from 'express';
import bodyParser from 'body-parser';
import { MongoClient } from 'mongodb';
import cors from 'cors';

const app = express();
let port = process.env.PORT || 4000; 

const username = 'user_test';
const password = 'CZ66ttLSf5s0GVe4';
const uri = `mongodb+srv://${username}:${password}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority`;

let usersCollection;

const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectToMongo() {
  try {
    await client.connect();
    const db = client.db('ThreatSculpt');
    usersCollection = db.collection('User');
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
    const user = await usersCollection.findOne({ username, password });
    if (user) {
      // Store the username in req.user
      req.user = { username };
      // Send success response with username
      res.status(200).json({ username });
      console.log(`[start-server] Login successful for username: '${username}'`);
    } else {
      // User not found or incorrect credentials, send error response
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Error authenticating user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/get-username', (req, res) => {
  // Check if username is stored in req.user
  if (req.user && req.user.username) {
    // Send back the username
    res.status(200).json({ username: req.user.username });
  } else {
    res.status(401).json({ error: 'User not authenticated' });
  }
});

// Start the server and connect to MongoDB
const server = app.listen(port, async () => {
  await connectToMongo();
  console.log(`Server is running on port ${server.address().port}`);
});