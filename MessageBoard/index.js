/*
Author: Rithik Mehta
Date: 11/6/23
Description: Message Board
*/


import express from "express";
import { engine } from "express-handlebars";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcrypt";
import { v4 } from "uuid";
import cookieParser from "cookie-parser";

// Open a promise connection
const dbPromise = open({
  filename: "./data.db",
  driver: sqlite3.Database,
});

// Create an Express application
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Set up Handlebars as the view engine
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", "./views");

app.use("/public", express.static("./public"));

// Check for user authentication based on auth token
app.use(async (req, res, next) => {
  if (!req.cookies.authToken) {
    return next();
  }
  const db = await dbPromise;
  const authToken = await db.get(
    "SELECT * FROM AuthTokens WHERE token=?;",
    req.cookies.authToken
  );
  if (!authToken) {
    return next();
  }
  const user = await db.get(
    "SELECT id FROM Users WHERE id=?",
    authToken.userId
  );
  if (!user) {
    return next();
  }
  req.user = user.id;
  next();
});

// Retrieve messages from the database and render home page
app.get("/", async (req, res) => {
  try {
    const db = await dbPromise;
    const messages = await db.all(
      `SELECT Messages.id, Messages.message, Users.username as author 
        FROM Messages LEFT JOIN Users WHERE Messages.authorId = Users.id;`
    );
    const user = req.user;
    res.render("home", { messages, user });
  } catch (e) {
    console.log("slash route", e);
    res.render("home", { error: "Something went wrong" });
  }
});

// Render registration page
app.get("/register", (req, res) => {
  if (req.user) {
    res.redirect("/");
    return;
  }
  res.render("register");
});

// Render login page
app.get("/login", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }
  res.render("login");
});

// User logout logic
app.get("/logout", async (req, res) => {
  if (!req.user || !req.cookies.authToken) {
    return res.redirect("/");
  }
  const db = await dbPromise;
  await db.run("DELETE FROM AuthTokens WHERE token=?", req.cookies.authToken);
  res.cookie("authToken", "", {
    expires: new Date(),
  });
  res.redirect("/");
});

// Store messages in the database
app.post("/message", async (req, res) => {
  const db = await dbPromise;
  await db.run(
    "INSERT INTO Messages (message, authorId) VALUES (?, ?);",
    req.body.message,
    req.user
  );
  res.redirect("/");
});

// user registration done through a try catch
app.post("/register", async (req, res) => {
  if (
    !req.body.username ||
    !req.body.password ||
    req.body.username.length === 0 ||
    req.body.password.length === 0
  ) {
    return res.render("register", { error: "invalid parameters" });
  }
  const db = await dbPromise;
  const passwordHash = await bcrypt.hash(req.body.password, 10);
  let result;
  try {
    result = await db.run(
      "INSERT INTO Users (username, passwordHash) VALUES (?, ?)",
      req.body.username,
      passwordHash
    );
  } catch (e) {
    console.log("register route", e);
    return res.render("register", {
      error:
        e.code === "SQLITE_CONSTRAINT"
          ? "Username taken"
          : "Something went wrong",
    });
  }
  const token = v4();
  await db.run(
    "INSERT INTO AuthTokens (token, userId) VALUES (?, ?);",
    token,
    result.lastID
  );
  res.cookie("authToken", token, {
    expires: new Date(Date.now() + 9000000000000),
  });
  res.redirect("/");
});

//  User login logic
app.post("/login", async (req, res) => {
  if (
    !req.body.username ||
    !req.body.password ||
    req.body.username.length === 0 ||
    req.body.password.length === 0
  ) {
    return res.render("login", { error: "Invalid parameters" });
  }
  const db = await dbPromise;
  const user = await db.get(
    "SELECT * FROM Users where username=?;",
    req.body.username
  );
  if (!user) {
    return res.render("login", { error: "Username or password is incorrect" });
  }
  const passwordMatch = await bcrypt.compare(
    req.body.password,
    user.passwordHash
  );
  if (!passwordMatch) {
    return res.render("login", { error: "Username or password is incorrect" });
  }
  const token = v4();
  await db.run(
    "INSERT INTO AuthTokens (token, userId) VALUES (?, ?);",
    token,
    user.id
  );
  res.cookie("authToken", token, {
    expires: new Date(Date.now() + 9000000000000),
  });
  res.redirect("/");
});

// Function for setup and migration
async function setup() {
  const db = await dbPromise;
  await db.migrate({ force: false });
  app.listen(8080, () => {
    console.log("listening on http://localhost:8080");
  });
}

// Call the setup function
setup();





