// This is for setting the route so that the website can calls and run functions that query the database
// This is so that the website won't runs the functions directly from the database
import express from 'express';
import { login } from '../server/dataService.js';

const router = express.Router();

// Route for user login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await login(username, password);
    if (user) {
      // User found, send success response
      res.status(200).json({ message: 'Login successful' });
    } else {
      // User not found or incorrect credentials, send error response
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Error handling login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;