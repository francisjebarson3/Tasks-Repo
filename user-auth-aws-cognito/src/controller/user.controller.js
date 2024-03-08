

const {sendResponse, validateInput}= require('../utils/validate');
import   {userLogin,verifyToken,userSignUp}  from  '@myorg/my-awesome-lib';



async function login(req,res) {
    try {
         const isValid = validateInput(req.body)
         if (!isValid)
             return sendResponse(400, { message: 'Invalid input' })
 
         const { email, password } = req.body;
         const response=await userLogin(email, password);
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
     const resp= await verifyToken(token);
     if(resp){
         return sendResponse(200, { payload: resp ,message:"Token is valid. Payload" });
     }else{
         return sendResponse(400, { message:"Token not valid" });
     }
 }
 
 async function signup(req, res) {
     try {
         const isValid = validateInput(req.body)
         if (!isValid)
             return sendResponse(400, { message: 'Invalid input' })
 
         const { email, password } = req.body;
         await userSignUp( email, password );
         return sendResponse(200, { message: 'User registration successful' })
     }
     catch (error) {
         const message = error.message ? error.message : 'Internal server error'
         return sendResponse(500, { message })
     }
 }

 module.exports={
    login ,verifyBearerToken, signup
 }