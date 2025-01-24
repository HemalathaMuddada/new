package com.example.demo.controller;

import java.util.List;

import javax.naming.AuthenticationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import com.example.demo.model.LoginRequest;
import com.example.demo.model.LoginResponse;
import com.example.demo.model.User;
import com.example.demo.service.JwtService;
import com.example.demo.service.UserDetailsServiceImpl;

@RestController
@RequestMapping("/api/auth")
public class CustomerController {

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) throws AuthenticationException {
    	Authentication authentication = authenticationManager.authenticate(
		    new UsernamePasswordAuthenticationToken(
		        request.getUserName(), 
		        request.getPaassword()
		    )
		);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtService.generateJwtToken(authentication);
		
		return ResponseEntity.ok(new LoginResponse(jwt));
    }
    
    @GetMapping("/allusers")
    public List<User> getAllUsers(){
    	return userDetailsServiceImpl.getUsers();
    }
}
