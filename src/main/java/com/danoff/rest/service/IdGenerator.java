package com.danoff.rest.service;

import java.util.UUID;

import org.springframework.stereotype.Service;

@Service
public class IdGenerator {
	
	public String generateId() {
		return UUID.randomUUID().toString();
	}

}
