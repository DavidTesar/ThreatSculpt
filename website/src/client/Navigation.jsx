import React from 'react'
import { Navbar, Nav, Dropdown } from 'react-bootstrap'
import { LinkContainer } from 'react-router-bootstrap'
export default function Navigation (props) {
  const {isLoggedIn, setIsLoggedIn} = props
  
  const handleLogout = () => {
    // Perform logout actions, e.g., clearing session, local storage, etc.
    // Then navigate to the home page and set isLoggedIn to false
    setIsLoggedIn(false); // Assuming setIsLoggedIn is a prop passed from parent component
  };
  let content =({})
  if (isLoggedIn) {
    content = (
      <LinkContainer to="/" >
            <Nav.Link onClick={handleLogout}> Log Out </Nav.Link>
          </LinkContainer>
    )
  } else {
    content = (
      <React.Fragment>
        <LinkContainer to="/login">
            <Nav.Link> Log In </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/signup">
            <Nav.Link> Sign Up </Nav.Link>
          </LinkContainer> 
        </React.Fragment>
    )
  }
  return (
    <Navbar expand="lg" className="bg-body-tertiary">
      <Navbar.Toggle aria-controls="basic-navbar-nav" />
      <Navbar.Collapse id="basic-navbar-nav">
        <Nav className="mx-auto">
          <LinkContainer to="/" >
            <Nav.Link> Home </Nav.Link>
          </LinkContainer>
          {content}
          <LinkContainer to="/setting">
            <Nav.Link> Setting </Nav.Link>
          </LinkContainer>
          <LinkContainer to="/search">
            <Nav.Link> Search </Nav.Link>
          </LinkContainer>
        </Nav>
      </Navbar.Collapse>
    </Navbar>
  );
}