import Express from 'express'
import dataRouter from './dataRoutes.mjs'
//import mongoose from 'mongoose'
//import MongoStore from 'connect-mongo'
//import { Mongo } from './mongoControllers.js'
import path from 'path'

//const store = new session.MemoryStore()
path.__dirname = path.resolve(path.dirname('C:/Users/TrinhAn/OneDrive - University of Wisconsin-Stout/Desktop/ThreatSculpt-main/web_db/public/index.html'))


const PORT = 3000
const app = new Express()

app.use(Express.json())


app.use((req, res, next) => {
  console.log(`${req.method} request at ${req.url}`)
  next()
})
// Statically serve the public folder
app.use(Express.static(path.join('C:/Users/TrinhAn/OneDrive - University of Wisconsin-Stout/Desktop/ThreatSculpt-main/web_db/public')))

app.use('/web/server', dataRouter)

app.get('*', (req, res) => {
  res.sendFile('index.html', { root: 'C:/Users/TrinhAn/OneDrive - University of Wisconsin-Stout/Desktop/ThreatSculpt-main/web_db/public' })
})

app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`)
})
