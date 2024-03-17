//import 'bootstrap/dist/css/bootstrap.min.css'
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './components/App'
import { BrowserRouter } from 'react-router-dom'
const root = createRoot(document.getElementById('root'))
root.render(
  <BrowserRouter>
  <React.Fragment>
    <p> TESTING IF DB WORKS </p>
    <App />
    </React.Fragment>
  </BrowserRouter>
);