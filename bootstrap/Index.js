<>
  <meta charSet="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, shrink-to-fit=no"
  />
  <title>Dashboard - ThreatSculpt</title>
  <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.min.css" />
  <link
    rel="stylesheet"
    href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i&display=swap"
  />
  <link rel="stylesheet" href="assets/fonts/fontawesome-all.min.css" />
  <link rel="stylesheet" href="assets/fonts/simple-line-icons.min.css" />
  <link rel="stylesheet" href="assets/css/bs-theme-overrides.css" />
  <link rel="stylesheet" href="assets/css/animate.min.css" />
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
            <a className="nav-link active" href="index.html">
              <i className="fas fa-tachometer-alt" />
              <span>Dashboard</span>
            </a>
          </li>
          <li className="nav-item">
            <a className="nav-link" href="profile.html">
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
          <div className="d-sm-flex justify-content-between align-items-center mb-4">
            <h3 className="text-dark mb-0">Start a scan</h3>
          </div>
          <div className="row">
            <div className="col-md-6 col-xl-3 mb-4">
              <div
                className="card shadow border-start-primary py-2"
                data-bss-hover-animate="pulse"
              >
                <div className="card-body">
                  <div className="row align-items-center no-gutters">
                    <div className="col me-2">
                      <div className="text-uppercase text-primary fw-bold text-xs mb-1">
                        <span>
                          <span
                            style={{ backgroundColor: "rgb(255, 255, 255)" }}
                          >
                            Simple Scan
                          </span>
                        </span>
                      </div>
                      <div className="text-dark fw-bold h5 mb-0">
                        <span />
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-broadcast-tower fa-2x text-gray-300" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-md-6 col-xl-3 mb-4">
              <div
                className="card shadow border-start-success py-2"
                data-bss-hover-animate="pulse"
              >
                <div className="card-body">
                  <div className="row align-items-center no-gutters">
                    <div className="col me-2">
                      <div className="text-uppercase text-success fw-bold text-xs mb-1">
                        <span>More Advanced</span>
                      </div>
                      <div className="text-dark fw-bold h5 mb-0" />
                    </div>
                    <div className="col-auto">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="1em"
                        height="1em"
                        fill="currentColor"
                        viewBox="0 0 16 16"
                        className="bi bi-radar fa-2x text-gray-300"
                      >
                        <path d="M6.634 1.135A7 7 0 0 1 15 8a.5.5 0 0 1-1 0 6 6 0 1 0-6.5 5.98v-1.005A5 5 0 1 1 13 8a.5.5 0 0 1-1 0 4 4 0 1 0-4.5 3.969v-1.011A2.999 2.999 0 1 1 11 8a.5.5 0 0 1-1 0 2 2 0 1 0-2.5 1.936v-1.07a1 1 0 1 1 1 0V15.5a.5.5 0 0 1-1 0v-.518a7 7 0 0 1-.866-13.847Z" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-md-6 col-xl-3 mb-4">
              <div
                className="card shadow border-start-info py-2"
                data-bss-hover-animate="pulse"
              >
                <div className="card-body">
                  <div className="row align-items-center no-gutters">
                    <div className="col me-2">
                      <div className="text-uppercase text-info fw-bold text-xs mb-1">
                        <span>Complex Scan</span>
                      </div>
                      <div className="row g-0 align-items-center">
                        <div className="col-auto">
                          <div className="text-dark fw-bold h5 mb-0 me-3" />
                        </div>
                      </div>
                    </div>
                    <div className="col-auto">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="1em"
                        height="1em"
                        fill="currentColor"
                        viewBox="0 0 16 16"
                        className="bi bi-shield-exclamation fa-2x text-gray-300"
                      >
                        <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56" />
                        <path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-md-6 col-xl-3 mb-4">
              <div
                className="card shadow border-start-warning py-2"
                data-bss-hover-animate="pulse"
              >
                <div className="card-body">
                  <div className="row align-items-center no-gutters">
                    <div className="col me-2">
                      <div className="text-uppercase text-warning fw-bold text-xs mb-1">
                        <span>Scans&nbsp;</span>
                      </div>
                      <div className="text-dark fw-bold h5 mb-0">
                        <span>#</span>
                      </div>
                    </div>
                    <div className="col-auto">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="1em"
                        height="1em"
                        viewBox="0 0 24 24"
                        strokeWidth={2}
                        stroke="currentColor"
                        fill="none"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="icon icon-tabler icon-tabler-scan-eye fa-2x text-gray-300"
                      >
                        <path stroke="none" d="M0 0h24v24H0z" fill="none" />
                        <path d="M4 8v-2a2 2 0 0 1 2 -2h2" />
                        <path d="M4 16v2a2 2 0 0 0 2 2h2" />
                        <path d="M16 4h2a2 2 0 0 1 2 2v2" />
                        <path d="M16 20h2a2 2 0 0 0 2 -2v-2" />
                        <path d="M7 12c3.333 -4.667 6.667 -4.667 10 0" />
                        <path d="M7 12c3.333 4.667 6.667 4.667 10 0" />
                        <path d="M12 12h-.01" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="row">
            <div
              className="col-lg-5 col-xl-4 offset-xxl-0"
              style={{ textAlign: "center" }}
            >
              <div className="card shadow mb-4">
                <div className="card-header d-flex justify-content-between align-items-center">
                  <h6 className="text-primary fw-bold m-0">Vulnerabilities</h6>
                  <div className="dropdown no-arrow">
                    <button
                      className="btn btn-link btn-sm dropdown-toggle"
                      aria-expanded="false"
                      data-bs-toggle="dropdown"
                      type="button"
                    >
                      <i className="fas fa-ellipsis-v text-gray-400" />
                    </button>
                    <div className="dropdown-menu shadow dropdown-menu-end animated--fade-in">
                      <p className="text-center dropdown-header">
                        dropdown header:
                      </p>
                      <a className="dropdown-item" href="#">
                        &nbsp;Action
                      </a>
                      <a className="dropdown-item" href="#">
                        &nbsp;Another action
                      </a>
                      <div className="dropdown-divider" />
                      <a className="dropdown-item" href="#">
                        &nbsp;Something else here
                      </a>
                    </div>
                  </div>
                </div>
                <div className="card-body" style={{ textAlign: "center" }}>
                  <div className="chart-area">
                    <canvas data-bss-chart='{"type":"doughnut","data":{"labels":["Direct","Social","Referral"],"datasets":[{"label":"","backgroundColor":["#4e73df","#1cc88a","#36b9cc"],"borderColor":["#ffffff","#ffffff","#ffffff"],"data":["50","30","15"]}]},"options":{"maintainAspectRatio":false,"legend":{"display":false,"labels":{"fontStyle":"normal"}},"title":{"fontStyle":"normal"}}}' />
                  </div>
                  <div className="text-center small mt-4">
                    <span className="me-2">
                      <i
                        className="fas fa-circle text-primary"
                        style={{
                          borderColor: "rgb(234,40,40)",
                          color: "rgb(235,34,46)"
                        }}
                      />
                      Critical
                    </span>
                    <span className="me-2">
                      <i className="fas fa-circle text-success" />
                      &nbsp;High
                    </span>
                    <span className="me-2">
                      <i className="fas fa-circle text-info" />
                      &nbsp;Medium
                    </span>
                  </div>
                </div>
              </div>
            </div>
            <div className="col">
              <div className="table-responsive">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Scans ID</th>
                      <th style={{ width: "429.188px" }}>Scan Date</th>
                      <th>Number of devices</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>ID</td>
                      <td>MM/DD/YYYY</td>
                      <td style={{ width: "367.125px" }}>#</td>
                    </tr>
                    <tr />
                    <tr />
                  </tbody>
                </table>
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
  </div>
</>
