import bcrypt from "bcryptjs";
import { client } from "./index.js";


async function genPassword(password) {
  const NO_OF_ROUNDS = 10; //difficulties
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS); //random string
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

async function getUserByEmail(email) {
  return await client
    .db("auth")
    .collection("users")
    .findOne({ email});
}

async function verifyUser(password) {
  return await client
    .db("auth")
    .collection("users")
    .findOne({ password:password});
}

async function verifyToken(token) {
  return await client
    .db("auth")
    .collection("users")
    .findOne({ password:token});
}

async function createUser(data) {
  return await client.db("auth").collection("users").insertOne(data);
}


// after forgot password,here the token will update the existing password
async function saveToken(data){
    let {email,token}=data
    return await client.db('auth').collection('users').updateOne({email},{$set:{password:token}})
    
}
// new password will be updated
async function updateUser(userData){
    const{email,password} = userData
    console.log(email,password)
    return await client.db('auth').collection('users').updateOne({email},{$set:{password:password}})
}


export {
    genPassword,
    createUser,
    getUserByEmail,
    saveToken,
    updateUser,
    verifyUser,
    verifyToken
}