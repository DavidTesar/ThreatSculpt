import { MongoClient } from 'mongodb';
import { quote_plus } from 'mongodb-uri';

// Define MongoDB credentials
const username = quote_plus('user_test');
const password = quote_plus('CZ66ttLSf5s0GVe4');

// Construct the MongoDB connection URI
const uri = "mongodb+srv://" + username + ":" + password + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority";

// Create a new client
const client = new MongoClient(uri);

// Function to connect to MongoDB and return the database and collections
export async function connectToMongo() {
  try {
    if (!client.isConnected()) {
      await client.connect();
      console.log('Connected to MongoDB');
    }
    const db = client.db('ThreatSculpt');
    const userCollection = db.collection('User');
    const userScanCollection = db.collection('ScanResults');
    return { db, userCollection, userScanCollection };
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    throw error; // Rethrow the error for handling in the caller
  }
}

// Function to close the MongoDB connection
export async function closeMongoConnection() {
  try {
    if (client.isConnected()) {
      await client.close();
      console.log('Disconnected from MongoDB');
    }
  } catch (error) {
    console.error('Failed to close MongoDB connection:', error);
    throw error; // Rethrow the error for handling in the caller
  }
}
