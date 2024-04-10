// This is for setting the route so that the website can calls and run functions that query the database
// This is so that the website won't runs the functions directly from the database
import express from 'express';
import { login, getUserInfo, getUserData } from '../server/dataService.js';

const router = express.Router();

// Route for user login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await login(username, password);
    if (user) {
      // User found, send success response with user ID
      res.status(200).json({ message: 'Login successful', userID: user.userID });
    } else {
      // User not found or incorrect credentials, send error response
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Error handling login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route for getting user information
router.post('/getUserInfo', async (req, res) => {
  const { username } = req.body;
  try {
    const userInfo = await getUserInfo(username);
    if (userInfo) {
      // User found, send user information
      res.status(200).json(userInfo);
    } else {
      // User not found, send error response
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error fetching user information:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route for getting scan results by user ID
router.post('/getUserData', async (req, res) => {
  const { userID } = req.body;
  try {
    console.log('Received userID:', userID);
    const scanResults = await getUserData(userID);
    res.status(200).json(scanResults);
  } catch (error) {
    console.error('Error fetching scan results:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route for getting user ID by username
router.post('/getUserID', async (req, res) => {
  const { username } = req.body;
  try {
    const userID = await getUserID(username);
    res.status(200).json({ userID });
  } catch (error) {
    console.error('Error fetching user ID:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;