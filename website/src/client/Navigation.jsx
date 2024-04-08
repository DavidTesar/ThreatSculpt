import React from 'react'
import { Navbar, Nav, Dropdown } from 'react-bootstrap'
import { LinkContainer } from 'react-router-bootstrap'

export default function Navigation () {
  
    //const navContent2 = (
    //  <LinkContainer to = "/setting" >
    //  <Nav.Link> Setting </Nav.Link>
    //</LinkContainer>
    //)
  return (
    <Navbar expand="lg" className="bg-body-tertiary">
      <Navbar.Toggle aria-controls="basic-navbar-nav" />
      <Navbar.Collapse id="basic-navbar-nav">
        <Nav className="mr-auto">
          <LinkContainer to="/login">
            <Nav.Link> LogIn </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/signup">
            <Nav.Link> Sign Up </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/devices">
            <Nav.Link> Devices </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/search">
            <Nav.Link> Search </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/">
            <Nav.Link> Home </Nav.Link>
          </LinkContainer>
        </Nav>
      </Navbar.Collapse>
    </Navbar>
  );
}