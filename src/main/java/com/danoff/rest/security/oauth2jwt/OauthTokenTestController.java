package com.danoff.rest.security.oauth2jwt;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
@Profile(value = "oauth2jwt")
public class OauthTokenTestController {
	
	@Autowired
	private TokenHelper tokenHelper;
	
	@RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    @ResponseStatus(value = HttpStatus.OK)
	public ResponseEntity<?> currentUser(Authentication auth) {
		Map<String, Object> model = tokenHelper.getExtraInfo(auth);
		return null;
	}
}
