package com.danoff.rest.security;

public enum ApplicationRoles {
	ADMIN("ADMIN"),
	USER("USER");
	
	private final String roleName;
	
	private ApplicationRoles(String roleName){
		this.roleName = roleName;
	}

	public String getRoleName() {
		return roleName;
	}

}
