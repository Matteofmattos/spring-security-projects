package com.DevTechsOne.springProj_Jwt.repository;

import com.DevTechsOne.springProj_Jwt.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
