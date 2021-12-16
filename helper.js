import bcrypt from "bcryptjs";
import { client } from "./index.js";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

async function genPassword(password) {
  const NO_OF_ROUNDS = 10; //difficulties
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS); //random string
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

async function getUserByEmail(email) {
  return await client.db("auth").collection("users").findOne({ email });
}

async function verifyUser(password) {
  return await client
    .db("auth")
    .collection("users")
    .findOne({ password: password });
}

async function verifyToken(token) {
  return await client
    .db("auth")
    .collection("users")
    .findOne({ password: token });
}

async function createUser(data) {
  return await client.db("auth").collection("users").insertOne(data);
}

// after forgot password,here the token will update the existing password
async function saveToken(data) {
  let { email, token } = data;
  return await client
    .db("auth")
    .collection("users")
    .updateOne({ email }, { $set: { password: token } });
}
// new password will be updated
async function updateUser(userData) {
  const { email, password } = userData;
  console.log(email, password);
  return await client
    .db("auth")
    .collection("users")
    .updateOne({ email }, { $set: { password: password } });
}

function Email(token, email) {
  var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASSWORD,
    },
  });
  const link = `http://localhost:3000/forgot-password/verify/${token}`;
  var mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: "Sending Email using Node.js",
    html: `<a href=${link}>
    Click the link to reset the password
    </a>`,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email Sent Successfully");
    }
  });
}

export {
  genPassword,
  createUser,
  getUserByEmail,
  saveToken,
  updateUser,
  verifyUser,
  verifyToken,
  Email,
};
