import express from "express";
import bcrypt from "bcryptjs";
import {
  genPassword,
  createUser,
  getUserByEmail,
  saveToken,
  updateUser,
  verifyUser,
  verifyToken,
  Email,
} from "../helper.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { auth } from "../middleware/auth.js";

dotenv.config();
const router = express.Router();

router.route("/").get(async (request, respond) => {
  respond.send("Password Reset");
});

//signup user - post
router.route("/signup").post(async (request, response) => {
  const { email, firstName, lastName, password } = request.body;
  const emailFromDB = await getUserByEmail(email); //check whether user already exist

  if (emailFromDB) {
    //if user name already exist
    response.status(401).send({ message: "email already exists " });
    return;
  }

  if (!email) {
    response.status(401).send({ message: "email should be provided" });
    return;
  }

  if (!firstName) {
    response.status(401).send({ message: "first name should be provided" });
    return;
  }
  if (!lastName) {
    response.status(401).send({ message: "last name should be provided" });
    return;
  }
  if (password.length < 8) {
    //check if the password length is greater than or equal to 8
    response.status(401).send({ message: "password must be longer" });
    return;
  }
  if (
    !/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)
  ) {
    response.status(401).send({ message: "Password pattern does not match" });
    return;
  }
  const hashedPassword = await genPassword(password);
  const result = await createUser({
    email,
    firstName,
    lastName,
    password: hashedPassword,
  });
  response.send({ message: "user created successfully" });
});

//login user - post
router.route("/signin").post(async (request, response) => {
  const { email, password } = request.body;
  const emailFromDB = await getUserByEmail(email);

  if (!emailFromDB) {
    //if user does not exist
    response.status(401).send({ message: "Invalid credentials" });
    return;
  }

  const storedPassword = emailFromDB.password;
  console.log("password", storedPassword);

  const isPasswordMatch = await bcrypt.compare(password, storedPassword); //comparing input password with existing password
  console.log("password", isPasswordMatch);

  if (isPasswordMatch) {
    const token = jwt.sign({ id: emailFromDB._id }, process.env.SECRET_KEY); //,{expiresIn:"3hours"}
    response.send({ message: "Successfully logged in", token: token }); //if password match
  } else {
    response.status(401).send({ message: "Invalid credentials" }); //if password does not match
  }
});

//forget password
router.route("/forgot-password").post(async (request, response) => {
  const { email } = request.body;
  const emailFromDB = await getUserByEmail(email);

  if (!emailFromDB) {
    //if user does not exist
    response.status(401).send({ message: "Email id does not exist" });
    return;
  }

  // If the user is valid, token  is  generated for the user
  const token = jwt.sign({ id: emailFromDB._id }, process.env.SECRET_KEY);

  //  The generated token will replace the old password for later verification
  const replacePassword = await saveToken({ email, token });

  // Email
  Email(token, email);
  // Using nodemailer the password reset link will be sent to the registered Email id
  return response.send({
    token,
    message: "Reset password link send to your email id",
  });
});

// After clicking the link in the email,which redirects to another page
router.route("/forgot-password/verify").get(async (request, response) => {
  // From the mail link the token was taken and it is placed in the header for further verification
  const token = await request.header("x-auth-token");

  const password = token;
  console.log("password", password);

  const tokenVerify = await verifyUser(password);

  // Using the token the user is verified in which the token replaced the old password before

  if (!tokenVerify) {
    //    If the token does not match
    return response.status(400).send({ message: "Invalid Credentials" });
  } else {
    return response.send({ message: "Matched" });
  }
});

router.route("/change-password").post(async (request, response) => {
  {
    // After the verification the new password is taken from the body of the request
    const { password, token } = request.body;

    if (password.length < 8) {
      response.status(401).send({ msg: "Password Must be longer" });
      return;
    }
    if (
      !/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)
    ) {
      response.status(401).send({ message: "Password pattern does not match" });
      return;
    }

    const data = await verifyToken(token);
    // The user is again verified using the same token which was sent before

    if (!data) {
      response.status(401).send({
        message: "link has been expired Please go back to forget password page",
      });
      return;
    }
    const { email } = data;

    // after the necessary verification the password is encrypted
    const hashedPassword = await genPassword(password);

    // After the generation of hashed password it will replace the token which is stored as a password
    const passwordUpdate = await updateUser({
      email,
      password: hashedPassword,
    });
    const result = await getUserByEmail(email);
    console.log("result", result);
    return response.send({ result, message: "Password Changed Successfully" });
  }
});

router.route("/successful").get(auth, (request, response) => {
  response.send({ message: "Successfully Logged In" });
});

export const authRouter = router;
