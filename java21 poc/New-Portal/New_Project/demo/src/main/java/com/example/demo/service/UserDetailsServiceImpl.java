package com.example.demo.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.config.SecurityConfig;
import com.example.demo.model.User;
import com.example.demo.repository.CustomerRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
    private CustomerRepository customerRepository;

//	@Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//	        return (UserDetails) customerRepository.findByEmail(username)
//	            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//	    
//    }
	@Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        User customer = customerRepository.findByEmail(username)
            .orElseThrow(() -> {
                log.error("User not found with email: {}", username);
                return new UsernameNotFoundException("User not found with email: " + username);
            });
        log.info("Found customer: {}", customer.getUsername());
        log.info("Password from DB: {}", customer.getPassword());
        if (customer != null) {
            System.out.println("Saved password in DB: " + customer.getPassword()+ customer.getUsername());
        }
        return customer;
    }
	
	public List<User> getUsers() {
		return customerRepository.findAll();
	}
}

