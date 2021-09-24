package jwtexample.jwtexample.controller;


import jwtexample.jwtexample.dto.LoginDto;
import jwtexample.jwtexample.dto.TokenDto;
import jwtexample.jwtexample.jwt.JwtFilter;
import jwtexample.jwtexample.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        //username과 userpassword를 파라미터로 받고 usernamepasswordAuthentication Token을 생성한다.
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //위에서 발급 받은 authenticationToken을 이용해서 authenticate(authenticationToken)에서 authenticate 메소드가 실행이 될때
        //우리가 만든 CustomUserDetailsService에서 loadUserByUsername 메소드가 실행이된다.
        //그 결과값으로 authentication 객체를 생성함
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        //그리고 그 객체를 security context에 저장함
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //그 인증 정보를 바탕으로 우리가 만든 tokenprovider 메서드를 통해서 토큰을 생성한다.
        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();

        //생성된 토큰을 response header 에 우리가 만든 토큰을 넣어준다
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        //TokenDto를 이용해서 ResponseBody에도 해당 토큰을 넣어주고 리턴
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}