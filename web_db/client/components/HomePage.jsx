//Should be the page shown when clicked on link/ or when opened from the local app
//Will pass the logic credentials if opened from local app
import React from 'react'
import { Navbar, Container } from 'react-bootstrap'
function HomePage () {

    return (
        <React.Fragment>
        <Navbar className="bg-body-tertiary">
        <Container>
          <Navbar.Brand href="#home">
            <img
              alt=""
              src="../../../website/public/logo192.png"
              width="30"
              height="30"
              className="d-inline-block align-top"
            />{' '}
            React Bootstrap
          </Navbar.Brand>
        </Container>
      </Navbar>
        </React.Fragment>
    )
}

export default HomePage