import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './components/TestDylan'
import { BrowserRouter } from 'react-router-dom'

const root = createRoot(document.getElementById('root'))

root.render(
  <BrowserRouter>
  <React.Fragment>
    <p> This is Dylan's Testing </p>
    <App />
    </React.Fragment>
  </BrowserRouter>
);