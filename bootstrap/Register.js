<>
  <meta charSet="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, shrink-to-fit=no"
  />
  <title>Register - ThreatSculpt</title>
  <link rel="stylesheet" href="assets/bootstrap/css/bootstrap.min.css" />
  <link
    rel="stylesheet"
    href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i&display=swap"
  />
  <link rel="stylesheet" href="assets/fonts/fontawesome-all.min.css" />
  <link rel="stylesheet" href="assets/css/bs-theme-overrides.css" />
  <div className="container">
    <div className="card shadow-lg o-hidden border-0 my-5">
      <div className="card-body p-0">
        <div className="row">
          <div className="col-lg-5 d-none d-lg-flex">
            <div
              className="flex-grow-1 bg-register-image"
              style={{ backgroundImage: 'url("assets/img/dogs/image2.jpeg")' }}
            />
          </div>
          <div className="col-lg-7">
            <div className="p-5">
              <div className="text-center">
                <h4 className="text-dark mb-4">Create an Account!</h4>
              </div>
              <form className="user">
                <div className="row mb-3">
                  <div className="col-sm-6 mb-3 mb-sm-0">
                    <input
                      className="form-control form-control-user"
                      type="text"
                      id="exampleFirstName"
                      placeholder="First Name"
                      name="first_name"
                    />
                  </div>
                  <div className="col-sm-6">
                    <input
                      className="form-control form-control-user"
                      type="text"
                      id="exampleLastName"
                      placeholder="Last Name"
                      name="last_name"
                    />
                  </div>
                </div>
                <div className="mb-3">
                  <input
                    className="form-control form-control-user"
                    type="email"
                    id="exampleInputEmail"
                    aria-describedby="emailHelp"
                    placeholder="Email Address"
                    name="email"
                  />
                </div>
                <div className="row mb-3">
                  <div className="col-sm-6 mb-3 mb-sm-0">
                    <input
                      className="form-control form-control-user"
                      type="password"
                      id="examplePasswordInput"
                      placeholder="Password"
                      name="password"
                    />
                  </div>
                  <div className="col-sm-6">
                    <input
                      className="form-control form-control-user"
                      type="password"
                      id="exampleRepeatPasswordInput"
                      placeholder="Repeat Password"
                      name="password_repeat"
                    />
                  </div>
                </div>
                <button
                  className="btn btn-primary d-block btn-user w-100"
                  type="submit"
                >
                  Register Account
                </button>
                <hr />
                <a
                  className="btn btn-primary d-block btn-google btn-user w-100 mb-2"
                  role="button"
                >
                  <i className="fab fa-google" />
                  &nbsp; Register with Google
                </a>
                <a
                  className="btn btn-primary d-block btn-facebook btn-user w-100"
                  role="button"
                >
                  <i className="fab fa-facebook-f" />
                  &nbsp; Register with Facebook
                </a>
                <hr />
              </form>
              <div className="text-center">
                <a className="small" href="forgot-password.html">
                  Forgot Password?
                </a>
              </div>
              <div className="text-center">
                <a className="small" href="login.html">
                  Already have an account? Login!
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</>
