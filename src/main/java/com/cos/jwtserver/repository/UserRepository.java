package com.cos.jwtserver.repository;

import com.cos.jwtserver.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username); // Jpa query method
}
