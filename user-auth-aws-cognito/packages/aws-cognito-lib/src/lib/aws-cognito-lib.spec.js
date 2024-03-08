import { userLogin ,verifyBearerToken } from './aws-cognito-lib';
describe('awsCognitoLib', () => {
  it('should work', () => {
    expect(userLogin(),verifyBearerToken()).toEqual('aws-cognito-lib');
  });
});
