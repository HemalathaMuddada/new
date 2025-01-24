package com.example.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.demo.model.User;

@Repository
public interface CustomerRepository extends JpaRepository<User, Long>,JpaSpecificationExecutor<User> {
	
	@Query("SELECT DISTINCT user FROM User user " 
//	+ "INNER JOIN FETCH user.authorities AS authorities "
			+ "WHERE lower(user.userName) = lower(:email)")
	Optional<User> findByEmail(String email);
}