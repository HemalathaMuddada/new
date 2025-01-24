package com.example.demo.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
	
	private String userName;
	
	private String paassword;

	public LoginRequest(String userName, String paassword) {
		super();
		this.userName = userName;
		this.paassword = paassword;
	}

}
