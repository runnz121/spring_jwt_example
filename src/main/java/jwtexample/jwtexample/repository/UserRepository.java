package jwtexample.jwtexample.repository;

import jwtexample.jwtexample.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


//JpaRepository를 extneds함으로서 findAll, save등의 메소드를 사용할 수 있음
public interface UserRepository extends JpaRepository<User, Long> {

    //쿼리 수행시 lazy조회가 아니고 eager조회로 authorities정보를 같이 갖고옴
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}