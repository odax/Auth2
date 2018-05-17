const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const LocalStrategy = require("passport-local");

const JwtStrategy = require("passport-jwt").Strategy;
const { ExtractJwt } = require("passport-jwt");

const User = require("./User");
const db = require("./config/db");

const secret = "this is my secret";

db
  .connectTo("jwtauth")
  .then(() => console.log("\n... API Connected to jwtauth Database ...\n"))
  .catch(err => {
    console.log("\n*** ERROR Connecting to MongoDB, is it running? ***\n", err);
  });

const server = express();
server.use(express.json());
server.use(express.json());

// passport settings (strategy) ****************************************************
const localStrategy = new LocalStrategy(function(username, password, done) {
  User.findOne({ username })
    .then(user => {
      if (!user) {
        done(null, false);
      } else {
        user
          .validatePassword(password)
          .then(isValid => {
            if (isValid) {
              const { _id, username } = user;
              return done(null, { _id, username }); // this ends in req.user
            } else {
              return done(null, false);
            }
          })
          .catch(err => {
            return done(err);
          });
      }
    })
    .catch(err => done(err));
});

// jwt settings (options / strategy)*****************************************************

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secret
};

const jwtStrategy = new JwtStrategy(jwtOptions, function(payload, done) {
  // here the token was decoded successfully
  User.findById(payload.sub)
    .then(user => {
      if (user) {
        done(null, user); // this is req.user
      } else {
        done(null, false);
      }
    })
    .catch(err => {
      done(err);
    });
});

//Middlewares*******************************************************

//**********Global

passport.use(localStrategy);
passport.use(jwtStrategy);

//***********Local

const passportOptions = { session: false };
const authenticate = passport.authenticate("local", passportOptions);
const protected = passport.authenticate("jwt", passportOptions);

//Helpers**************************************************************

function makeToken(user) {
  const timestamp = new Date().getTime();
  const payload = {
    sub: user._id,
    iat: timestamp,
    username: user.username
  };
  const options = {
    expiresIn: "24h"
  };

  return jwt.sign(payload, secret, options);
}

//Default Route**********************************************************
module.exports = function(server) {
  server.get("/", function(req, res) {
    res.send({ api: "up and running" });
  });
};

//This is broken ^^

//Routes*******************************************************************

server.post("/register", function(req, res) {
  const user = new User(req.body);
  //Remeber 1 line up and 2 lines below = User.create(req.body)
  user
    .save()
    .then(user => {
      const token = makeToken(user);
      res.status(201).json({ user, token });
    })
    .catch(err => res.status(500).send(err));
});

server.post("/login", authenticate, (req, res) => {
  res.status(200).json({ token: makeToken(req.user), user: req.user });
});

server.get("/users", authenticate, (req, res) => {
  User.find().then(users => res.send(users));
});

server.get("/users", protected, (req, res) => {
  User.find()
    .select("username")
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      res.status(500).json(err);
    });
});

// server.get('/logout', (req, res) => {
// if (req.session) {
//     req.session.destroy(function(err) {
//     if (err) {
//         res.send('error');
//     } else {
//         res.send('good bye');
//     }
//     });
// }
// });

//set up server listener
server.listen(8000, () => console.log("\n=== api running on 8k ===\n"));
