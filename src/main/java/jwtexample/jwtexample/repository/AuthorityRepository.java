package jwtexample.jwtexample.repository;

import jwtexample.jwtexample.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}