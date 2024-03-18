import { MongoClient, ServerApiVersion } from 'mongodb'
import dotenv from 'dotenv'

dotenv.config({path: "C:/Users/TrinhAn/OneDrive - University of Wisconsin-Stout/Desktop/ThreatSculpt-main/web_db/server/.env"})
const dbPassword = process.env.DB_PASSWORD
const dbUsername = process.env.DB_USERNAME

const uri = `mongodb+srv://${dbUsername}:${dbPassword}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version

export const Mongo = new MongoClient(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverApi:
    {
      version: ServerApiVersion.v1,
      strict: true
    }
  })

export default function queryMongoDatabase (queryCallback, databaseName) {
    queryCallback(Mongo.db(databaseName))
      .catch(err => {
        console.error('Failed to query database')
        console.error(err)
      })
  }