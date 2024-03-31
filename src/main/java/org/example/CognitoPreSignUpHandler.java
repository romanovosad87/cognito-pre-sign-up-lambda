package org.example;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AdminLinkProviderForUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminLinkProviderForUserResult;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordRequest;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.InvalidParameterException;
import com.amazonaws.services.cognitoidp.model.ListUsersRequest;
import com.amazonaws.services.cognitoidp.model.ListUsersResult;
import com.amazonaws.services.cognitoidp.model.MessageActionType;
import com.amazonaws.services.cognitoidp.model.ProviderUserIdentifierType;
import com.amazonaws.services.cognitoidp.model.UserType;
import com.amazonaws.services.cognitoidp.model.UsernameExistsException;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.CognitoUserPoolPreSignUpEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents a Cognito pre-sign-up handler responsible for handling pre-sign-up events in a Cognito user pool.
 * <p>
 * The class uses a facade design pattern to encapsulate the interactions with the AWS Cognito Identity Provider
 * and provide a simplified interface for handling pre-sign-up events.
 */
public class CognitoPreSignUpHandler {
    private static final String ACCESS_KEY_ID = System.getenv("ACCESS_KEY_ID");
    private static final String ACCESS_KEY_SECRET = System.getenv("ACCESS_KEY_SECRET");
    private static final String USER_POOL_ID = System.getenv("USER_POOL_ID");
    private static final String REGION_NAME = System.getenv("REGION_NAME");
    private static final String TRIGGER_SOURCE_EXTERNAL_PROVIDER = "PreSignUp_ExternalProvider";
    private static final String EMAIL = "email";
    private static final String CONFIRMED = "CONFIRMED";
    private static final String COGNITO = "Cognito";
    private static final String COGNITO_SUBJECT = "Cognito_Subject";

    /**
     * This method is invoked when a pre-sign-up event occurs in the Cognito user pool.
     * It checks if the trigger source is an external provider, creates a user if it does not exist,
     * changes the user's status to password confirmed, and links users if necessary.
     *
     * @param event   The pre-sign-up event received from the Cognito user pool.
     * @param context The AWS Lambda context object.
     * @return The modified pre-sign-up event.
     */
    public CognitoUserPoolPreSignUpEvent handleRequest(CognitoUserPoolPreSignUpEvent event,
                                                       Context context) {
        LambdaLogger logger = context.getLogger();
        logger.log("Function '" + context.getFunctionName() + "' called");

        if (event.getTriggerSource().equals(TRIGGER_SOURCE_EXTERNAL_PROVIDER)) {
            logger.log(String.format("Trigger Source: %s", event.getTriggerSource()));

            if (event.getRequest().getUserAttributes().containsKey(EMAIL)) {
                String email = event.getRequest().getUserAttributes().get(EMAIL);
                logger.log("Email is " + email);

                try {
                    AdminCreateUserResult newUserResult = createUser(email, logger);
                    logger.log(String.format("newUserResult with username: %s was created,  status %s",
                            newUserResult.getUser().getUsername(), newUserResult.getUser().getUserStatus()));
                    changeToPasswordConfirmed(newUserResult.getUser().getUsername(), logger);
                    linkUser(event, newUserResult.getUser().getUsername(), logger);
                    return event;
                } catch (UsernameExistsException e) {
                    logger.log("Catching UsernameExistsException - error code: " + e.getErrorCode()
                            + ", message: " + e.getErrorMessage() + " " + e);

                    ListUsersResult listUsersResult = listUsers(email);
                    logger.log(String.format("List of Users with email: %s is %s ",
                            email, listUsersResult.getUsers()));

                    List<UserType> userType = getUserTypeIfExistNativeUser(listUsersResult);
                    logger.log(String.format("UserType: %s", userType));

                    if (!userType.isEmpty()) {
                        try {
                            linkUser(event, userType.get(0).getUsername(), logger);
                        } catch (InvalidParameterException ex) {
                            logger.log("Catching InvalidParameterException - error code: " + ex.getErrorCode()
                                    + ", message: " + ex.getErrorMessage());
                            return event;
                        }
                    }
                }
            }
        }
        logger.log("event response" + event.getResponse());
        logger.log("Username: " + event.getUserName());
        return event;
    }

    /**
     * Returns an instance of the AWS Cognito Identity Provider client.
     *
     * @return An instance of the AWS Cognito Identity Provider client.
     */
    private AWSCognitoIdentityProvider getAWSCognitoIdentityProvider() {
        final BasicAWSCredentials basicAWSCredentials = new BasicAWSCredentials(ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);

        return AWSCognitoIdentityProviderClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(basicAWSCredentials))
                .withRegion(REGION_NAME)
                .build();
    }

    /**
     * Creates a user in the Cognito user pool.
     *
     * @param email  The email address of the user to be created.
     * @param logger The Lambda logger object.
     * @return The result of the user creation operation.
     */
    private AdminCreateUserResult createUser(String email, LambdaLogger logger) {
        logger.log("Invoking adminCreateUser");
        AdminCreateUserRequest adminCreateUserRequest = new AdminCreateUserRequest()
                .withUsername(email)
                .withUserPoolId(USER_POOL_ID)
                .withUserAttributes(new AttributeType().withName(EMAIL).withValue(email))
                .withMessageAction(MessageActionType.SUPPRESS);

        AWSCognitoIdentityProvider awsCognitoIdentityProvider = getAWSCognitoIdentityProvider();
        AdminCreateUserResult adminCreateUserResult
                = awsCognitoIdentityProvider.adminCreateUser(adminCreateUserRequest);
        logger.log("End of adminCreateUser, username: " + adminCreateUserResult.getUser().getUsername());
        return adminCreateUserResult;
    }

    /**
     * Changes the user's status to password confirmed in the Cognito user pool.
     *
     * @param username The username of the user.
     * @param logger   The Lambda logger object.
     */
    private void changeToPasswordConfirmed(String username, LambdaLogger logger) {
        logger.log("Invoking adminSetUserPassword");
        AdminSetUserPasswordRequest adminSetUserPasswordRequest = new AdminSetUserPasswordRequest()
                .withPassword(generatePassword())
                .withUserPoolId(USER_POOL_ID)
                .withUsername(username)
                .withPermanent(true);

        AWSCognitoIdentityProvider awsCognitoIdentityProvider = getAWSCognitoIdentityProvider();

        AdminSetUserPasswordResult adminSetUserPasswordResult
                = awsCognitoIdentityProvider.adminSetUserPassword(adminSetUserPasswordRequest);
        logger.log("End of adminSetUserPassword, status code: "
                + adminSetUserPasswordResult.getSdkHttpMetadata().getHttpStatusCode());
    }

    /**
     * Generates a random password for the user.
     *
     * @return The randomly generated password.
     */
    private String generatePassword() {
      // implement random generate password logic
        return null;
    }

    /**
     * Lists users in the Cognito user pool based on the provided email address.
     *
     * @param email The email address of the user.
     * @return The list of users matching the specified email address.
     */
    private ListUsersResult listUsers(String email) {
        ListUsersRequest listUsersRequest = new ListUsersRequest()
                .withUserPoolId(USER_POOL_ID)
                .withFilter("%s = \"".formatted(EMAIL) + email + "\"");

        AWSCognitoIdentityProvider awsCognitoIdentityProvider = getAWSCognitoIdentityProvider();
        return awsCognitoIdentityProvider.listUsers(listUsersRequest);
    }

    /**
     * Retrieves user types if native users exist in the Cognito user pool.
     *
     * @param listUsersResult The result of the list users operation.
     * @return The list of user types for native users.
     */
    private List<UserType> getUserTypeIfExistNativeUser(ListUsersResult listUsersResult) {
        if (listUsersResult != null && listUsersResult.getUsers() != null
                && !listUsersResult.getUsers().isEmpty()) {
            return listUsersResult.getUsers()
                    .stream()
                    .filter(user -> user.getUserStatus().equals(CONFIRMED))
                    .toList();
        }
        return new ArrayList<>();
    }

    /**
     * Links users in the Cognito user pool.
     *
     * @param event    The pre-sign-up event received from the Cognito user pool.
     * @param username The username of the user.
     * @param logger   The Lambda logger object.
     */
    private void linkUser(CognitoUserPoolPreSignUpEvent event,
                          String username, LambdaLogger logger) {
        logger.log("invoking linkUser");
        ProviderUserIdentifierType destinationUser = new ProviderUserIdentifierType()
                .withProviderAttributeValue(username)
                .withProviderName(COGNITO);
        logger.log(String.format("Destination user: %s", destinationUser));

        String providerName = event.getUserName().split("_")[0];
        String providerNameFirstLetterUpperCase = providerName.substring(0, 1).toUpperCase()
                + providerName.substring(1);

        ProviderUserIdentifierType sourceUser = new ProviderUserIdentifierType()
                .withProviderAttributeName(COGNITO_SUBJECT)
                .withProviderAttributeValue(event.getUserName().split("_")[1])
                .withProviderName(providerNameFirstLetterUpperCase);
        logger.log(String.format("Source user: %s", sourceUser));

        AdminLinkProviderForUserRequest request = new AdminLinkProviderForUserRequest()
                .withUserPoolId(event.getUserPoolId())
                .withDestinationUser(destinationUser)
                .withSourceUser(sourceUser);

        AWSCognitoIdentityProvider awsCognitoIdentityProvider = getAWSCognitoIdentityProvider();
        AdminLinkProviderForUserResult result = awsCognitoIdentityProvider.adminLinkProviderForUser(request);
        logger.log(String.format("End of linkUser for user with username: %s and response code: %s",
                event.getUserName(), result.getSdkHttpMetadata().getHttpStatusCode()));
    }
}
