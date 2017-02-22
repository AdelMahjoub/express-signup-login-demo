var express = require("express");
var bodyParser = require("body-parser");
var expressValidator = require("express-validator");
var path = require("path");
var mongojs = require("mongojs");
var bcrypt = require("bcrypt-nodejs");
var passport = require("passport");
var localStrategy = require("passport-local").Strategy;
var session = require("express-session");
var ObjectId = mongojs.ObjectId;

// Connection to Subscribers database
var db = mongojs("mongodb://127.0.0.1:27017/Subscribers", ["users"]);

// Number of rounds for password hashing
var ROUNDS = 10;

// Views global variable
// Only used to render back the provided data if an error occurs in users regeistration
// for the user convenience, to not rewrite everything
var user = {
  userName:"",
  firstName: "",
  lastName: "",
  eMail: "",
  password: "",
  bio: ""
}

var app = express();

// Set views
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// Static files Middleware
app.use(express.static(path.join(__dirname, "public")));
// body-parser Middleware
app.use(bodyParser.urlencoded({extended: false}));
// express-validator Middleware
app.use(expressValidator({
  errorFormatter: function(param, msg, value) {
      var namespace = param.split('.')
      , root    = namespace.shift()
      , formParam = root;

    while(namespace.length) {
      formParam += '[' + namespace.shift() + ']';
    }
    return {
      param : formParam,
      msg   : msg,
      value : value
    };
  }
}));

app.use(session({ 
  secret: "keyboard cat",
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(function(req, res, next) {
  res.locals.title = "Welcome";
  res.locals.errors = []; // No errors when the page is first visited
  // Input fields values, 
  // keep the values if an error occur,
  // for user convenience, empty when the signup page is
  // visited for the first time
  res.locals.user = user; 
  next();
});

// Landing page
app.get("/", function(req, res) {
  db.users.find(function(err, docs) {
    res.render("index", {
      users: docs
    });
  });
});

// User registration page
app.get("/signup", function(req, res) {
  res.render("signup");
});

//Login page
app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/profile", function(req, res) {
  var user = req.user;
  console.log(user);
  if(user) {
    res.locals.user = user;
    res.render("profile");
    return;
  }
  res.redirect("/login");
});

// Register user
app.post("/signup", function(req, res) {
  
  req.checkBody("userName", "User name is required").notEmpty();
  req.checkBody("password", "Password is required").notEmpty();
  req.checkBody("eMail", "e-mail is required").notEmpty();
  req.checkBody("userName", "User name: please use only alphabetic or numeric values").isAlphanumeric();
  req.checkBody("password", "Password: length must be between 4 and 16").len(4, 16);
  req.checkBody("eMail", "Email: must be a valid e-mail adreess").isEmail();

  // Provided data validation
  req.getValidationResult().then(function(result) {
    // provided user's data  
    var newUser = {
      userName: req.body.userName,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: req.body.password,
      eMail: req.body.eMail,
      bio: req.body.bio
    }
    // render back the provided data, if validation fails
    res.locals.user = newUser;

    // Check for errors
    if(!result.isEmpty()) {
      // Back to the signup page,
      return res.render("signup", {
        errors: result.array(),
      });
    }  
    // Check if the provided user name is already registred
    db.users.find({userName: req.body.userName}, function(err, doc) {
      if(err) {
        // Back to the signup page, 
        return res.render("signup", {
          errors: [{msg: "An error ocuured, please try again."}]
        });
      } //ENDIF 

      // Provided User name already exists
      if(doc.length !== 0) {
        return res.render("signup", {
          errors: [{msg: "This user name is already registred"}]
        });
      } //ENDIF

      // Check if the provided email is already registred
      db.users.find({eMail: req.body.eMail}, function(err, doc) {
        if(err) {
          return res.render("signup", {
            errors: [{msg: "An error occured, please try again."}]
          });
        } // ENDIF

        // Provided email already exists
        if(doc.length !== 0) {
          return res.render("signup", {
            errors: [{msg: "This email adress is already registred"}]
          });
        } //ENDIF

        // Hash the user password before inserting the new user
        var noop = function() {}; // A do nothing function
        // generate salt
        bcrypt.genSalt(ROUNDS, function(err, salt) {
          if(err) {
            return res.render("signup", {
              errors: [{msg: "Sorry, an error occured, please try again"}]
            });
          }
          // hashing the provided password
          bcrypt.hash(req.body.password, salt, noop, function(err, hashedPassword) {
            if(err) {
              return res.render("signup", {
                errors: [{msg: "Sorry, an error occured, please try again"}]
              });
            }
            // Provided UserName and Email adress are unique
            // the password is hashed,
            // Insert a new user and redirect to the login page
            db.users.insert({
              userName: req.body.userName,
              firstName: req.sanitize("firstName").escape(),
              lastName: req.sanitize("lastName").escape(),
              password: hashedPassword,
              eMail: req.body.eMail,
              bio: req.sanitize("bio").escape(),
              createdAt: (new Date()).toLocaleTimeString()
            }); 

            //Back to home page
            res.redirect("/login");
          });
        }); // END OF HASHING

      }); // END OF DUPLICATE EMAIL CHECK

    }) // END OF DUPLICATE USERNAME CHECK

  }); //END OF VALIDATION FUNCTION

}); // END OF POST ROUTE /signup

// Login 
// Passport strategy
passport.use(new localStrategy (
  function(username, password, done) {
    db.users.findOne({userName: username}, function(err, user) {
      if(err) { return done(err); }
      if(!user) {
        return done(null, false, {message: 'Incorrect password or username.'});
      }
      bcrypt.compare(password, user.password, function(err, res) {
        if(err) { return false; }
        if(!res) {
          return done(null, false, {message: "Incorrect password or username"});
        }
        return done(null, user);
      });
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  db.users.findOne({_id: ObjectId(id)}, function(err, user) {
    done(err, user);
  });
});

// Login user 
app.post("/login", function(req, res, next) {
  passport.authenticate("local", function(err, user, info) {
    if(err) { return next(err); }
    if(!user) {
      return res.render("login", {errors: [info]});
    }
    req.logIn(user, function(err) {
      if(err) { return next(err); }
        res.redirect("/profile");
    });
  })(req, res, next);
});

app.use(function(req, res) {
  res.status(404).render("404");
});

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});