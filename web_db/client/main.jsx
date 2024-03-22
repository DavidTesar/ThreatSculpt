import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './components/App'
import { BrowserRouter } from 'react-router-dom'
import HomePage from './components/HomePage'

const root = createRoot(document.getElementById('root'))
root.render(
  <BrowserRouter>
  <React.Fragment>
    <h1>This is running</h1>
    <HomePage></HomePage>
    <p> TESTING IF this WORKS </p>
    <App />
    </React.Fragment>
  </BrowserRouter>
);