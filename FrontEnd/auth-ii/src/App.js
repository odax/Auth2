import React, { Component } from "react";
import { Route, withRouter } from "react-router-dom";

import logo from "./logo.svg";
import "./App.css";
import Signin from "./Signin";
import Users from "./Users";

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <h1 className="App-title">Login Website</h1>

          {localStorage.getItem("token") && (
            <button onClick={this.signout}>Sign out</button>
          )}
        </header>

        <Route path="/signin" component={Signin} />
        <Route path="/users" component={Users} />
      </div>
    );
  }

  signout = () => {
    localStorage.removeItem("token");
    this.props.history.push("/signin");
  };
}

export default withRouter(App);
