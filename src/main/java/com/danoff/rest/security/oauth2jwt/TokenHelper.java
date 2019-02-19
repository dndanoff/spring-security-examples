package com.danoff.rest.security.oauth2jwt;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

@Service
@Profile(value = "oauth2jwt")
public class TokenHelper {
	
	@Autowired
	private TokenStore tokenStore;
	
	public Map<String, Object> getExtraInfo(Authentication auth) {
	    OAuth2AuthenticationDetails oauthDetails
	      = (OAuth2AuthenticationDetails) auth.getDetails();
	    return (Map<String, Object>) oauthDetails.getDecodedDetails();
	}
	
	public Map<String, Object> getExtraInfo(OAuth2Authentication auth) {
	    OAuth2AuthenticationDetails details
	      = (OAuth2AuthenticationDetails) auth.getDetails();
	    OAuth2AccessToken accessToken = tokenStore
	      .readAccessToken(details.getTokenValue());
	    return accessToken.getAdditionalInformation();
	}
}
