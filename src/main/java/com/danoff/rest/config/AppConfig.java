package com.danoff.rest.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@ConfigurationProperties(prefix = "danoff")
public class AppConfig {
	private final Environment env;

	private Realm realm = new Realm();
	private Security security = new Security();

	@Autowired
	public AppConfig(Environment env) {
		this.env = env;
	}

	public Realm getRealm() {
		return realm;
	}

	public Security getSecurity() {
		return security;
	}

	public class Realm {
		private String admin;
		private String api;

		public String getAdmin() {
			return admin;
		}

		public void setAdmin(String admin) {
			this.admin = admin;
		}

		public String getApi() {
			return api;
		}

		public void setApi(String api) {
			this.api = api;
		}

	}

	public class Security {
		private String encoderStrength;
		private String key;
		private String tokenValidity;

		public String getEncoderStrength() {
			return encoderStrength;
		}

		public void setEncoderStrength(String encoderStrength) {
			this.encoderStrength = encoderStrength;
		}

		public String getKey() {
			return key;
		}

		public void setKey(String key) {
			this.key = key;
		}

		public String getTokenValidity() {
			return tokenValidity;
		}

		public void setTokenValidity(String tokenValidity) {
			this.tokenValidity = tokenValidity;
		}
	}
}