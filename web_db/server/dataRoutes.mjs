// This is for setting the route so that the website can calls and run functions that query the database
// This is so that the website won't runs the functions directly from the database
import Express from 'express'
import { login } from './dataServices.mjs'

const dataRouter = new Express.Router()

dataRouter.post('/login', login) // open

// Make the router available to import in other files
export default dataRouter 