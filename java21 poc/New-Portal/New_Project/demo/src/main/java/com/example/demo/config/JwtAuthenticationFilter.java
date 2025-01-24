package com.example.demo.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.model.User;
import com.example.demo.service.JwtService;
import com.example.demo.service.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private final JwtService jwtService;
	   private final UserDetailsServiceImpl userDetailsService;

	   public JwtAuthenticationFilter(JwtService jwtService, UserDetailsServiceImpl userDetailsService) {
	       this.jwtService = jwtService;
	       this.userDetailsService = userDetailsService;
	   }

	   @Override
	   protected void doFilterInternal(HttpServletRequest request, 
	                                 HttpServletResponse response, 
	                                 FilterChain chain) throws ServletException, IOException {
	       try {
	           String token = getTokenFromRequest(request);
	           log.debug("Received token: {}", token);

	           if (StringUtils.hasText(token)) {
	               String username = jwtService.getUserNameFromJwtToken(token);
	               log.debug("Extracted username: {}", username);

	               User userDetails = userDetailsService.loadUserByUsername(username);
	               
	               UsernamePasswordAuthenticationToken authentication = 
	                   new UsernamePasswordAuthenticationToken(userDetails, 
	                                                         null,
	                                                         userDetails.getAuthorities());
	               
	               authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
	               SecurityContextHolder.getContext().setAuthentication(authentication);
	           }
	       } catch (Exception e) {
	           log.error("Token validation error: {}", e.getMessage());
	       }

	       chain.doFilter(request, response);
	   }

	   private String getTokenFromRequest(HttpServletRequest request) {
	       String bearerToken = request.getHeader("Authorization");
	       log.debug("Extracted token from header: {}", bearerToken);
	       if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
	           String token = bearerToken.substring(7);
	           log.debug("Extracted token from header: {}", token);
	           return token;
	       }
	       return null;
	   }
    }

	
