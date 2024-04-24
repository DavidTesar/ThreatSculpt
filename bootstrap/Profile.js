<>
  <meta charSet="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, shrink-to-fit=no"
  />
  <title>Profile - ThreatSculpt</title>
  <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.min.css" />
  <link
    rel="stylesheet"
    href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i&display=swap"
  />
  <link rel="stylesheet" href="assets/fonts/fontawesome-all.min.css" />
  <link rel="stylesheet" href="assets/fonts/simple-line-icons.min.css" />
  <link rel="stylesheet" href="assets/css/bs-theme-overrides.css" />
  <div id="wrapper">
    <nav
      className="navbar align-items-start sidebar sidebar-dark accordion bg-gradient-primary p-0 navbar-dark"
      style={{ background: "rgb(0,0,0)" }}
    >
      <div className="container-fluid d-flex flex-column p-0">
        <a
          className="navbar-brand d-flex justify-content-center align-items-center sidebar-brand m-0"
          href="#"
        >
          <div className="sidebar-brand-icon rotate-n-15">
            <i className="icon-globe" style={{ fontSize: 36 }} />
          </div>
          <div className="sidebar-brand-text mx-3">
            <span>ThreatSculpt</span>
          </div>
        </a>
        <hr className="sidebar-divider my-0" />
        <ul className="navbar-nav text-light" id="accordionSidebar">
          <li className="nav-item">
            <a className="nav-link" href="index.html">
              <i className="fas fa-tachometer-alt" />
              <span>Dashboard</span>
            </a>
          </li>
          <li className="nav-item">
            <a className="nav-link active" href="profile.html">
              <i className="fas fa-user" />
              <span>Profile</span>
            </a>
          </li>
          <li className="nav-item">
            <a className="nav-link" href="table.html">
              <i className="fas fa-table" />
              <span>Table</span>
            </a>
          </li>
          <li className="nav-item">
            <a className="nav-link" href="login.html">
              <i className="far fa-user-circle" />
              <span>Login</span>
            </a>
          </li>
          <li className="nav-item">
            <a className="nav-link" href="register.html">
              <i className="fas fa-user-circle" />
              <span>Register</span>
            </a>
          </li>
        </ul>
        <div className="text-center d-none d-md-inline">
          <button
            className="btn rounded-circle border-0"
            id="sidebarToggle"
            type="button"
          />
        </div>
      </div>
    </nav>
    <div className="d-flex flex-column" id="content-wrapper">
      <div id="content">
        <nav className="navbar navbar-expand bg-white shadow mb-4 topbar static-top navbar-light">
          <div className="container-fluid">
            <button
              className="btn btn-link d-md-none rounded-circle me-3"
              id="sidebarToggleTop"
              type="button"
            >
              <i className="fas fa-bars" />
            </button>
            <h3 className="text-dark mb-0">
              <strong>Dashboard</strong>
            </h3>
            <ul className="navbar-nav flex-nowrap ms-auto">
              <li className="nav-item dropdown d-sm-none no-arrow">
                <a
                  className="dropdown-toggle nav-link"
                  aria-expanded="false"
                  data-bs-toggle="dropdown"
                  href="#"
                >
                  <i className="fas fa-search" />
                </a>
                <div
                  className="dropdown-menu dropdown-menu-end p-3 animated--grow-in"
                  aria-labelledby="searchDropdown"
                >
                  <form className="me-auto navbar-search w-100">
                    <div className="input-group">
                      <input
                        className="bg-light form-control border-0 small"
                        type="text"
                        placeholder="Search for ..."
                      />
                      <div className="input-group-append">
                        <button className="btn btn-primary py-0" type="button">
                          <i className="fas fa-search" />
                        </button>
                      </div>
                    </div>
                  </form>
                </div>
              </li>
              <li className="nav-item dropdown no-arrow mx-1">
                <div className="nav-item dropdown no-arrow">
                  <a
                    className="dropdown-toggle nav-link"
                    aria-expanded="false"
                    data-bs-toggle="dropdown"
                    href="#"
                  />
                  <div className="dropdown-menu dropdown-menu-end dropdown-list animated--grow-in">
                    <h6 className="dropdown-header">alerts center</h6>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="me-3">
                        <div className="bg-primary icon-circle">
                          <i className="fas fa-file-alt text-white" />
                        </div>
                      </div>
                      <div>
                        <span className="small text-gray-500">
                          December 12, 2019
                        </span>
                        <p>A new monthly report is ready to download!</p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="me-3">
                        <div className="bg-success icon-circle">
                          <i className="fas fa-donate text-white" />
                        </div>
                      </div>
                      <div>
                        <span className="small text-gray-500">
                          December 7, 2019
                        </span>
                        <p>$290.29 has been deposited into your account!</p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="me-3">
                        <div className="bg-warning icon-circle">
                          <i className="fas fa-exclamation-triangle text-white" />
                        </div>
                      </div>
                      <div>
                        <span className="small text-gray-500">
                          December 2, 2019
                        </span>
                        <p>
                          Spending Alert: We've noticed unusually high spending
                          for your account.
                        </p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item text-center small text-gray-500"
                      href="#"
                    >
                      Show All Alerts
                    </a>
                  </div>
                </div>
              </li>
              <li className="nav-item dropdown no-arrow mx-1">
                <div className="nav-item dropdown no-arrow">
                  <a
                    className="dropdown-toggle nav-link"
                    aria-expanded="false"
                    data-bs-toggle="dropdown"
                    href="#"
                  />
                  <div className="dropdown-menu dropdown-menu-end dropdown-list animated--grow-in">
                    <h6 className="dropdown-header">alerts center</h6>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="dropdown-list-image me-3">
                        <img
                          className="rounded-circle"
                          src="assets/img/avatars/avatar4.jpeg"
                        />
                        <div className="bg-success status-indicator" />
                      </div>
                      <div className="fw-bold">
                        <div className="text-truncate">
                          <span>
                            Hi there! I am wondering if you can help me with a
                            problem I've been having.
                          </span>
                        </div>
                        <p className="small text-gray-500 mb-0">
                          Emily Fowler - 58m
                        </p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="dropdown-list-image me-3">
                        <img
                          className="rounded-circle"
                          src="assets/img/avatars/avatar2.jpeg"
                        />
                        <div className="status-indicator" />
                      </div>
                      <div className="fw-bold">
                        <div className="text-truncate">
                          <span>
                            I have the photos that you ordered last month!
                          </span>
                        </div>
                        <p className="small text-gray-500 mb-0">
                          Jae Chun - 1d
                        </p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="dropdown-list-image me-3">
                        <img
                          className="rounded-circle"
                          src="assets/img/avatars/avatar3.jpeg"
                        />
                        <div className="bg-warning status-indicator" />
                      </div>
                      <div className="fw-bold">
                        <div className="text-truncate">
                          <span>
                            Last month's report looks great, I am very happy
                            with the progress so far, keep up the good work!
                          </span>
                        </div>
                        <p className="small text-gray-500 mb-0">
                          Morgan Alvarez - 2d
                        </p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item d-flex align-items-center"
                      href="#"
                    >
                      <div className="dropdown-list-image me-3">
                        <img
                          className="rounded-circle"
                          src="assets/img/avatars/avatar5.jpeg"
                        />
                        <div className="bg-success status-indicator" />
                      </div>
                      <div className="fw-bold">
                        <div className="text-truncate">
                          <span>
                            Am I a good boy? The reason I ask is because someone
                            told me that people say this to all dogs, even if
                            they aren't good...
                          </span>
                        </div>
                        <p className="small text-gray-500 mb-0">
                          Chicken the Dog · 2w
                        </p>
                      </div>
                    </a>
                    <a
                      className="dropdown-item text-center small text-gray-500"
                      href="#"
                    >
                      Show All Alerts
                    </a>
                  </div>
                </div>
                <div
                  className="shadow dropdown-list dropdown-menu dropdown-menu-end"
                  aria-labelledby="alertsDropdown"
                />
              </li>
              <div className="d-none d-sm-block topbar-divider" />
              <li className="nav-item dropdown no-arrow">
                <div className="nav-item dropdown no-arrow">
                  <a
                    className="dropdown-toggle nav-link"
                    aria-expanded="false"
                    data-bs-toggle="dropdown"
                    href="#"
                  >
                    <span className="d-none d-lg-inline me-2 text-gray-600 small">
                      User 1
                    </span>
                  </a>
                  <div className="dropdown-menu shadow dropdown-menu-end animated--grow-in">
                    <a className="dropdown-item" href="#">
                      <i className="fas fa-user fa-sm fa-fw me-2 text-gray-400" />
                      &nbsp;Profile
                    </a>
                    <a className="dropdown-item" href="#">
                      <i className="fas fa-cogs fa-sm fa-fw me-2 text-gray-400" />
                      &nbsp;Settings
                    </a>
                    <a className="dropdown-item" href="#">
                      <i className="fas fa-list fa-sm fa-fw me-2 text-gray-400" />
                      &nbsp;Activity log
                    </a>
                    <div className="dropdown-divider" />
                    <a className="dropdown-item" href="#">
                      <i className="fas fa-sign-out-alt fa-sm fa-fw me-2 text-gray-400" />
                      &nbsp;Logout
                    </a>
                  </div>
                </div>
              </li>
            </ul>
          </div>
        </nav>
        <div className="container-fluid">
          <h3 className="text-dark mb-4">Profile</h3>
          <div className="row mb-3">
            <div className="col-lg-4">
              <div className="card mb-3">
                <div className="card-body text-center shadow">
                  <img
                    className="rounded-circle mb-3 mt-4"
                    src="assets/img/dogs/image2.jpeg"
                    width={160}
                    height={160}
                  />
                  <div className="mb-3">
                    <button className="btn btn-primary btn-sm" type="button">
                      Change Photo
                    </button>
                  </div>
                </div>
              </div>
              <div className="card shadow mb-4" />
            </div>
            <div className="col-lg-8">
              <div className="row mb-3 d-none">
                <div className="col">
                  <div className="card text-white bg-primary shadow">
                    <div className="card-body">
                      <div className="row mb-2">
                        <div className="col">
                          <p className="m-0">Peformance</p>
                          <p className="m-0">
                            <strong>65.2%</strong>
                          </p>
                        </div>
                        <div className="col-auto">
                          <i className="fas fa-rocket fa-2x" />
                        </div>
                      </div>
                      <p className="text-white-50 small m-0">
                        <i className="fas fa-arrow-up" />
                        &nbsp;5% since last month
                      </p>
                    </div>
                  </div>
                </div>
                <div className="col">
                  <div className="card text-white bg-success shadow">
                    <div className="card-body">
                      <div className="row mb-2">
                        <div className="col">
                          <p className="m-0">Peformance</p>
                          <p className="m-0">
                            <strong>65.2%</strong>
                          </p>
                        </div>
                        <div className="col-auto">
                          <i className="fas fa-rocket fa-2x" />
                        </div>
                      </div>
                      <p className="text-white-50 small m-0">
                        <i className="fas fa-arrow-up" />
                        &nbsp;5% since last month
                      </p>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row">
                <div className="col">
                  <div className="card shadow mb-3">
                    <div className="card-header py-3">
                      <p className="text-primary m-0 fw-bold">User Settings</p>
                    </div>
                    <div className="card-body">
                      <form>
                        <div className="row">
                          <div className="col">
                            <div className="mb-3">
                              <label className="form-label" htmlFor="username">
                                <strong>Username</strong>
                              </label>
                              <input
                                className="form-control"
                                type="text"
                                id="username"
                                placeholder="user.name"
                                name="username"
                              />
                            </div>
                          </div>
                          <div className="col">
                            <div className="mb-3">
                              <label className="form-label" htmlFor="email">
                                <strong>Email Address</strong>
                              </label>
                              <input
                                className="form-control"
                                type="email"
                                id="email"
                                placeholder="user@example.com"
                                name="email"
                              />
                            </div>
                          </div>
                        </div>
                        <div className="row">
                          <div className="col">
                            <div className="mb-3">
                              <label
                                className="form-label"
                                htmlFor="first_name"
                              >
                                <strong>First Name</strong>
                              </label>
                              <input
                                className="form-control"
                                type="text"
                                id="first_name"
                                placeholder="John"
                                name="first_name"
                              />
                            </div>
                          </div>
                          <div className="col">
                            <div className="mb-3">
                              <label className="form-label" htmlFor="last_name">
                                <strong>Last Name</strong>
                              </label>
                              <input
                                className="form-control"
                                type="text"
                                id="last_name"
                                placeholder="Doe"
                                name="last_name"
                              />
                            </div>
                          </div>
                        </div>
                        <div className="mb-3">
                          <button
                            className="btn btn-primary btn-sm"
                            type="submit"
                          >
                            Save Settings
                          </button>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <footer className="bg-white sticky-footer">
        <div className="container my-auto">
          <div className="text-center my-auto copyright">
            <span>Copyright © ThreatSculpt 2024</span>
          </div>
        </div>
      </footer>
    </div>
    <a className="border rounded d-inline scroll-to-top" href="#page-top">
      <i className="fas fa-angle-up" />
    </a>
  </div>
</>
