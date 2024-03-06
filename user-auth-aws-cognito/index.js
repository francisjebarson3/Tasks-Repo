const express = require('express');
const AWS = require('aws-sdk');
const {CognitoJwtVerifier}= require( "aws-jwt-verify");

const { sendResponse, validateInput } = require("./utils/validate");
const webApp = express();
webApp.use(express.urlencoded({ extended: true }));
webApp.use(express.json());
const dotenv = require('dotenv');
dotenv.config();
const PORT = process.env.PORT;
const CLIENT_ID =  process.env.CLIENT_ID;
const USER_POOL_ID = process.env.USER_POOL_ID;
const AWS_ACCESS_KEY_ID=process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS=  process.env.AWS_SECRET_ACCESS;  
const AWS_REGION=process.env.AWS_REGION;

const cognito = new AWS.CognitoIdentityServiceProvider({ 
    "accessKeyId": AWS_ACCESS_KEY_ID, 
    "secretAccessKey": AWS_SECRET_ACCESS, 
    "region": AWS_REGION
});


const verifier = CognitoJwtVerifier.create({
  userPoolId: USER_POOL_ID,
  tokenUse: "id",
  clientId: CLIENT_ID,
});

webApp.post('/login', async (req, res) => {
  const resp = await login(req, res);
  res.send(resp);
});

webApp.post('/verify', async (req, res) => {
    const resp = await privateFunction(req, res);
    res.send(resp);
});

webApp.post('/signup', async (req, res) => {
    const resp = await signup(req, res);
    res.send(resp);
});

webApp.listen(PORT, () => {
    console.log(`Server is up and running at ${PORT}`);
});

async function login(event) {
   try {
        const isValid = validateInput(event.body)
        if (!isValid)
            return sendResponse(400, { message: 'Invalid input' })

        const { email, password } = event.body;
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

async function privateFunction(req) {
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

async function signup(event) {
    try {
        const isValid = validateInput(event.body)
        if (!isValid)
            return sendResponse(400, { message: 'Invalid input' })

        const { email, password } = event.body;
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