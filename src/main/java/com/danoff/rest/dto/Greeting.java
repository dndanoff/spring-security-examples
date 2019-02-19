package com.danoff.rest.dto;

public class Greeting {
	
	private String id;
	private String messge;
	
	public Greeting() {
		this(null, null);
	}
	
	public Greeting(String id, String messge) {
		this.id = id;
		this.messge = messge;
	}
	
	public String getId() {
		return id;
	}
	public String getMessge() {
		return messge;
	}

	public void setId(String id) {
		this.id = id;
	}

	public void setMessge(String messge) {
		this.messge = messge;
	}
	
}
