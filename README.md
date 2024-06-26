# Cognito Pre-sign-up Lambda

This AWS Lambda function, `CognitoPreSignUpHandler`, is designed to handle pre-sign-up events in an AWS Cognito user pool. It ensures seamless user registration and linkage for both email-password and social sign-up methods like Google or Facebook.

## Overview

When a pre-sign-up event is triggered in the Cognito user pool, this Lambda function intercepts the event and executes a series of actions:

1. Checks if the trigger source is an external provider.
2. Creates a new user if one does not exist.
3. Changes the user's status to password confirmed.
4. Links users if necessary.

## Usage

### Configuration

Before using this Lambda function, ensure the following environment variables are set:

- `ACCESS_KEY_ID`: AWS access key ID.
- `ACCESS_KEY_SECRET`: AWS secret access key.
- `USER_POOL_ID`: ID of the Cognito user pool.
- `REGION_NAME`: AWS region name.

### Trigger

This Lambda function is triggered by pre-sign-up events in the Cognito user pool.

### Dependencies

This Lambda function relies on the AWS SDK for Java to interact with the Cognito Identity Provider.

### Deployment

To deploy this Lambda function, package the code along with its dependencies using Maven and the Maven Shade plugin. Then, upload the deployment package to AWS Lambda.

### Execution

When a pre-sign-up event occurs, AWS Cognito invokes this Lambda function. The function processes the event, performs the necessary actions, and returns the modified event.

## Code Structure

- `CognitoPreSignUpHandler`: Main class representing the Lambda function.
- `handleWRequest`: Method to handle pre-sign-up events.
- `getAWSCognitoIdentityProvider`: Method to retrieve the AWS Cognito Identity Provider client.
- `createUser`: Method to create a user in the Cognito user pool.
- `changeToPasswordConfirmed`: Method to change a user's status to password confirmed.
- `generatePassword`: Method to generate a random password for the user.
- `listUsers`: Method to list users in the Cognito user pool based on email.
- `getUserTypeIfExistNativeUser`: Method to retrieve user types if native users exist in the user pool.
- `linkUser`: Method to link users in the Cognito user pool.

## Conclusion

This Lambda function simplifies the process of handling pre-sign-up events in AWS Cognito, ensuring a seamless user registration and linkage experience for both email-password and social sign-up methods. It enhances the functionality of AWS Cognito, making it more versatile and developer-friendly.

