import queryMongoDatabase from '../server/mongoControllers'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
import { connectToMongo } from './mongoControllers.js';
dotenv.config()
import { users_collection } from '../server/mongoControllers.js';

// Function to handle user login
export async function login(username, password, usersCollection) {
  try {
    const user = await usersCollection.findOne({ username, password });
    return user;
  } catch (error) {
    console.error('Error authenticating user:', error);
    throw new Error('Internal server error');
  }
}