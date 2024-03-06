

const dotenv = require( 'dotenv');
const {sendResponse, validateInput}= require('../utils/validate');
const {verifier,cognito}= require('../utils/awsUtils');
dotenv.config();
const CLIENT_ID =  process.env.CLIENT_ID;
const USER_POOL_ID = process.env.USER_POOL_ID;

async function login(req,res) {
    try {
         const isValid = validateInput(req.body)
         if (!isValid)
             return sendResponse(400, { message: 'Invalid input' })
 
         const { email, password } = req.body;
         const params = {
             AuthFlow: "ADMIN_NO_SRP_AUTH",
             UserPoolId: USER_POOL_ID,
             ClientId: CLIENT_ID,
             AuthParameters: {
                 USERNAME: email,
                 PASSWORD: password
             }
             
         }
         const response = await cognito.adminInitiateAuth(params).promise();
         return sendResponse(200, { message: 'Success', token: response.AuthenticationResult.IdToken })
     }
     catch (error) {
         const message = error.message ? error.message : 'Internal server error'
         return sendResponse(500, { message })
     }
 }
 
 async function verifyBearerToken(req, res) {
     const token=req.headers['authorization'].replace('Bearer ','');
     console.log(`token::: ${token}`);
     try {
         const payload = await verifier.verify(
             token // the JWT as string
         );
         console.log("Token is valid. Payload:", payload);
         return sendResponse(200, { payload: payload ,message:"Token is valid. Payload" });
       } catch {
         console.log("Token not valid!");
         return sendResponse(400, { message:"Token not valid" });
       }
 
    
 }
 
 async function signup(req, res) {
     try {
         const isValid = validateInput(req.body)
         if (!isValid)
             return sendResponse(400, { message: 'Invalid input' })
 
         const { email, password } = req.body;
         const params = {
             UserPoolId: USER_POOL_ID,
             Username: email.split("@")[0],
             UserAttributes: [
                 {
                     Name: 'email',
                     Value: email
                 },
                 {
                     Name: 'email_verified',
                     Value: 'true'
                 }],
             MessageAction: 'SUPPRESS'
         }
         const response = await cognito.adminCreateUser(params).promise();
         if (response.User) {
             const paramsForSetPass = {
                 Password: password,
                 UserPoolId: USER_POOL_ID,
                 Username: email,
                 Permanent: true
             };
             await cognito.adminSetUserPassword(paramsForSetPass).promise()
         }
         return sendResponse(200, { message: 'User registration successful' })
     }
     catch (error) {
         const message = error.message ? error.message : 'Internal server error'
         return sendResponse(500, { message })
     }
 }

 module.exports={
    login, verifyBearerToken, signup
 }