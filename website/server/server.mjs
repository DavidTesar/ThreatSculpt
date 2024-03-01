import Express from 'express'
import dataRouter from 'dataRoutes.js'
import mongoose from 'mongoose'
import MongoStore from 'connect-mongo'
import { Mongo, url } from 'mongoControllers.js'
import path from 'path'

import schedule from 'node-schedule'

//const store = new session.MemoryStore()
path.__dirname = path.resolve(path.dirname('../public/index.html'))


const PORT = 3000
const app = new Express()

app.use(Express.json())


app.use((req, res, next) => {
  console.log(`${req.method} request at ${req.url}`)
  next()
})
// Statically serve the public folder
app.use(Express.static(path.join('../public')))

app.use('/website/server', dataRouter)

app.get('*', (req, res) => {
  res.sendFile('index.html', { root: '../public' })
})

app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`)
})
