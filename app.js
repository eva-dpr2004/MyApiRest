const express = require("express");
const dotenv = require("dotenv");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config({ path: "./.env" });
const app = express();

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
});

db.connect((error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Pour une fois ça marche :)");
  }
});

app.use(express.json());

// Generation du token
function generateToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
  };

  const options = {
    expiresIn: process.env.JWT_EXPIRES_IN
  };

  return jwt.sign(payload, process.env.JWT_SECRET, options);
}

function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "Access denied. Token missing." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
    if (error) {
      return res.status(401).json({ error: "Invalid token." });
    }

    req.user = decoded;
    next();
  });
}

// Crée un nouvel utilisateur
app.post("/users", (req, res) => {
  const { lastName, firstName, password, role, email } = req.body;

  bcrypt.hash(password, 10, (error, hashedPassword) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: "L'operation à échoué frère" });
    } else {
      const newUser = { lastName, firstName, password: hashedPassword, role, email };
      db.query("INSERT INTO users SET ?", newUser, (error, result) => {
        if (error) {
          console.log(error);
          res.status(500).json({ error: "L'opération à échoué" });
        } else {
          const user = { id: result.insertId, ...newUser };
          const token = generateToken(user);
          res.status(201).json({
            message: "L'utilisateur est crée, bienvenue.",
            token: token,
          });
        }
      });
    }
  });
});

// protected route
app.get("/users", (req, res) => {
  db.query("SELECT * FROM users", (error, results) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: "Failed to retrieve users" });
    } else {
      res.status(200).json(results);
    }
  });
});

// protected route
app.get("/user/:id", (req, res) => {
  const userId = req.params.id;

  db.query("SELECT * FROM users WHERE userId = ?", userId, (error, results) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: "Erreur de serveur" });
    } else if (results.length === 0) {
      res.status(404).json({ error: "Eh fréro je trouve pas ce gars la hein" });
    } else {
      res.status(200).json(results[0]);
    }
  });
});

// Update♥
app.put("/user/:id", (req, res) => {
  const userId = req.params.id;
  const { lastName, firstName, password, role, email } = req.body;
  const updatedUser = { lastName,firstName, password, role, email };

  db.query(
    "UPDATE users SET ? WHERE id = ?",
    [updatedUser, userId],
    (error, result) => {
      if (error) {
        console.log(error);
        res.status(500).json({ error: "Failed to update the user" });
      } else if (result.affectedRows === 0) {
        res.status(404).json({ error: "User not found" });
      } else {
        res.status(200).json({ message: "User updated successfully" });
      }
    }
  );
});

// Delete♥
app.delete("/user/:id", (req, res) => {
  const userId = req.params.id;

  db.query("DELETE FROM users WHERE id = ?", userId, (error, result) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: "Failed to delete the user" });
    } else if (result.affectedRows === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.status(200).json({ message: "User deleted successfully" });
    }
  });
});

// Login♥
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", email, (error, results) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: "Erreur du serveur" });
    } else if (results.length === 0) {
      res.status(401).json({ error: "Invalid email or password" });
    } else {
      const user = results[0];
      bcrypt.compare(password, user.password, (error, isMatch) => {
        if (error) {
          console.log(error);
          res.status(500).json({ error: "Failed to login" });
        } else if (isMatch) {
          const token = generateToken(user);
          res.status(200).json({
            message: "Login successful",
            token: token,
          });
        } else {
          res.status(401).json({ error: "Invalid email or password" });
        }
      });
    }
  });
});

app.listen(2023);
