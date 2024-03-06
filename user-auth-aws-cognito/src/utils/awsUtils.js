const AWS  = require( 'aws-sdk');
const {CognitoJwtVerifier} = require( 'aws-jwt-verify');

const AWS_ACCESS_KEY_ID=process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS=  process.env.AWS_SECRET_ACCESS;  
const AWS_REGION=process.env.AWS_REGION;
const USER_POOL_ID = process.env.USER_POOL_ID;
const CLIENT_ID =  process.env.CLIENT_ID;


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

module.exports={verifier,cognito,AWS};