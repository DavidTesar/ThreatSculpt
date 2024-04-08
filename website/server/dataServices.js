import queryMongoDatabase from '../server/mongoControllers'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
import { connectToMongo } from './mongoControllers.js';
dotenv.config()
import { userCollection, scanResultsCollection, getScanResultsByUserID, getUserDataByUserID } from '../server/mongoControllers.js';

// Function to handle user login
export async function login(username, password, userCollection) {
  try {
    const user = await userCollection.findOne({ username, password });
    if (user) {
      // If user is found, return an object with login status and user data
      return { loggedIn: true, user };
    } else {
      // If user is not found, return an object with login status only
      return { loggedIn: false };
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
    console.log('Fetched user information:', user);
    return user;
  } catch (error) {
    console.error('Error fetching user information:', error);
    throw new Error('Internal server error');
  }
}

// Function to fetch scan results by user ID
export async function getScanResultsByUserID(userID) {
  try {
    console.log('Received userID in getScanResultsByUserID:', userID);
    const { db, scanResultsCollection } = await connectToMongo();
    const scanResultsCursor = await scanResultsCollection.find({ userID });
    const scanResults = await scanResultsCursor.toArray();
    console.log('Fetched scan results:', scanResults);
    return scanResults;
  } catch (error) {
    console.error('Error fetching scan results:', error);
    throw new Error('Internal server error');
  }
}