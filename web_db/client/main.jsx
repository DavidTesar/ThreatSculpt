//import 'bootstrap/dist/css/bootstrap.min.css'
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './components/App'
import { BrowserRouter } from 'react-router-dom'
const root = createRoot(document.getElementById('root'))
root.render(
  <BrowserRouter>
  <React.Fragment>
    <h1> TESTING IF THIS WORKS </h1>
    <App />
    </React.Fragment>
  </BrowserRouter>
);