package com.DevTechsOne.springProj_Jwt.repository;

import com.DevTechsOne.springProj_Jwt.entities.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {

}
