import React, { useState, useEffect } from 'react';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv'

dotenv.config({path: "../web_db/server/.env"})
const dbPassword = process.env.DB_PASSWORD
const dbUsername = process.env.DB_USERNAME

const uri = `mongodb+srv://${dbUsername}:${dbPassword}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

function App() {
  const [data, setData] = useState([]);

  useEffect(() => {
    // Function to fetch data
    const fetchData = async () => {
      // Connect to MongoDB
      const client = new MongoClient(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      try {
        await client.connect(); // Connect to the MongoDB server

        // Access the database and collection
        const db = client.db('ThreatSculpt');
        const collection = db.collection('ScanResults');

        // Query the collection for data
        const result = await collection.find({}).toArray();
        setData(result); // Update the component state with the fetched data
      } catch (error) {
        console.error('Error fetching data:', error);
      } finally {
        await client.close(); // Close the MongoDB connection
      }
    };

    fetchData(); // Call the fetchData function
  }, []); // Empty dependency array ensures this effect runs only once when the component mounts

  return (
    <div>
      <h1>Data from MongoDB</h1>
      <ul>
        {data.map((item, index) => (
          <li key={index}>
            <h3>{item.name}</h3>
            <p>{item.description}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
