package com.example.demo.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponse {

	private String token;

	public LoginResponse(String token) {
		super();
		this.token = token;
	}
	
	
}
