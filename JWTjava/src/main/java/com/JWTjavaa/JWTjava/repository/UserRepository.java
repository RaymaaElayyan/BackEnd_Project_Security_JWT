package com.JWTjavaa.JWTjava.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.JWTjavaa.JWTjava.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);


}
