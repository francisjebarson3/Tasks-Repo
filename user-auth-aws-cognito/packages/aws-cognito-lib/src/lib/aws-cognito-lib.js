
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

export async function userLogin(email,password){
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
  return response;
}


export async function verifyToken(token){

  try {
    const payload = await verifier.verify(
      token // the JWT as string
    );
    console.log("Token is valid. Payload:");
    return payload
  } catch {
    console.log("Token not valid!");
    return null;
  }
}

export async function userSignUp(email,password){
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
}



