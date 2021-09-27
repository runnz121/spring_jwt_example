package jwtexample.jwtexample.service;

import java.util.Collections;
import java.util.Optional;


import jwtexample.jwtexample.dto.UserDto;
import jwtexample.jwtexample.entity.Authority;
import jwtexample.jwtexample.entity.User;
import jwtexample.jwtexample.exception.DuplicateMemberException;
import jwtexample.jwtexample.repository.UserRepository;
import jwtexample.jwtexample.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //회원 가입 로직 수행 메소드
    @Transactional
    public User signup(UserDto userDto) {
        //userDto를 파라미터로 받아 이를 바탕으로 username이 있는지 findonewithauthoritiesbyusername을 통해 db에 있는지 확인해봄
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        //유저정보가 없다면 권한과 유저정보를 저장
        //빌더 패턴의 장점
        Authority authority = Authority.builder()
                //저장시 저장될 유저의 권한 정보를 입력
                //이 권한을 바탕으로 권한 검증이 이루어짐
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority)) //한객의 객체만 저장 가능항 컬렉션
                .activated(true)
                .build();

        return userRepository.save(user);
    }


    //Username을 파라미터로 받아서 username을 기준으로 권한정보를 갖고옴
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    //현재 securitycontext에 저장되어있는 유저정보와 권한정보를 받아옴
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}