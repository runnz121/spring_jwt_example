package jwtexample.jwtexample.controller;



import jwtexample.jwtexample.dto.UserDto;
import jwtexample.jwtexample.entity.User;
import jwtexample.jwtexample.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
    }

    @PostMapping("/test-redirect")
    public void testRedirect(HttpServletResponse response) throws IOException {
        response.sendRedirect("/api/user");
    }


    //UserDto를 파라미터로 받아 UserService의 signup메소드를 호출한다.
    @PostMapping("/signup")
    public ResponseEntity<User> signup(
            @Valid @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    //@PreAuthorize 어노테이션을 통해 user, admin 권한 두가지 모두 호출 가능하게끔 구현
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<User> getMyUserInfo(HttpServletRequest request) {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    //@PreAuthorize 어노테이션을 통해 admin 권한만 호출하게끔 구현
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
        //service에서 만들었던 userservice의 getuserwithAuthorities 메소드를 통해서 username과 권한 정보를 리턴함
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}