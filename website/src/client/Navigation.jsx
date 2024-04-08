import React from 'react'
import { Navbar, Nav, Dropdown } from 'react-bootstrap'
import { LinkContainer } from 'react-router-bootstrap'

export default function Navigation () {
  
  return (
    <Navbar expand="lg" className="bg-body-tertiary">
      <Navbar.Toggle aria-controls="basic-navbar-nav" />
      <Navbar.Collapse id="basic-navbar-nav">
        <Nav className="mx-auto">
          <LinkContainer to="/" >
            <Nav.Link> Home </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/login">
            <Nav.Link> Login </Nav.Link>
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
        </Nav>
      </Navbar.Collapse>
    </Navbar>
  );
}