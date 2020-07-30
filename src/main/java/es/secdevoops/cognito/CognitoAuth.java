package es.secdevoops.cognito;

import java.util.HashMap;
import java.util.Map;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.util.StringUtils;

public class CognitoAuth {

	//Replace with the correct values
	private static final String COGNITO_CLIENT_ID = "MY_COGNITO_CLIENT_ID";
	private static final String COGNITO_POOL_ID = "MY_COGNITO_POOL_ID";
	private static final String AWS_ACCESS_KEY = "MY_AWS_ACCESS_KEY";
	private static final String AWS_SECRET_KEY = "MY_AWS_SECRET_KEY";
	private static final Regions REGION = Regions.US_EAST_1; 


	private AWSCognitoIdentityProvider cognitoClient;

	public String login(String username,String password){
		String idToken = null;
		Map<String,String> authParams = new HashMap<String,String>();
		authParams.put("USERNAME", username);
		authParams.put("PASSWORD", password);
		AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
				.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
				.withAuthParameters(authParams)
				.withClientId(COGNITO_CLIENT_ID)
				.withUserPoolId(COGNITO_POOL_ID);
		AdminInitiateAuthResult authResponse = getCognitoClient().adminInitiateAuth(authRequest);
		if(StringUtils.isNullOrEmpty(authResponse.getChallengeName())){
			idToken = authResponse.getAuthenticationResult().getIdToken();
		}else {
			idToken = changePassword(username,password,password,authResponse.getSession());
		}
		return idToken;
	}

	/**
	 * This method is called if a user is logging in for the first time. Once the User is confirmed, login() method is
	 * enough to authenticate the user from the next time.
	 * @return ID Token
	 */
	public String changePassword(String username,String password,String resetPassword,String session){
		String idToken = null;
		Map<String,String> challengeResponses = new HashMap<String,String>();
		challengeResponses.put("USERNAME", username);
		challengeResponses.put("PASSWORD", password);
		challengeResponses.put("NEW_PASSWORD", password);
		AdminRespondToAuthChallengeRequest finalRequest = new AdminRespondToAuthChallengeRequest()
				.withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
				.withChallengeResponses(challengeResponses)
				.withClientId(COGNITO_CLIENT_ID)
				.withUserPoolId(COGNITO_POOL_ID)
				.withSession(session);
		AdminRespondToAuthChallengeResult challengeResponse = getCognitoClient().adminRespondToAuthChallenge(finalRequest);
		if(StringUtils.isNullOrEmpty(challengeResponse.getChallengeName())){
			idToken = challengeResponse.getAuthenticationResult().getIdToken();
		}
		return idToken;
	}

	private AWSCognitoIdentityProvider getCognitoClient(){
		if(cognitoClient == null) {
			cognitoClient = AWSCognitoIdentityProviderClient.builder()
					.withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(AWS_ACCESS_KEY,
							AWS_SECRET_KEY))).withRegion(REGION).build();
		}
		return cognitoClient;
	}
}
