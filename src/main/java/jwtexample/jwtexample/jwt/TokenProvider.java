package jwtexample.jwtexample.jwt;


import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;


//토큰의 유효성 검증을 담당하는 클래스


//InitializingBean을 implementP하여 afterPropertiesSet 을 override한 이유?
//빈이 component 로 생성이 되고 주입 받은 후 secret값을 base64 디코딩 해서 key 변수에 할당

//1번 : component로 빈이 생성이된다.
@Component
public class TokenProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds;

    private Key key;

    //2번: 의존성 주입을 받는다(생성자로)
    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    //2번에서 생성된 secret값을 base64 로 디코드 하고 key 변수에 할당
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     *  Authentication 객체의 권한정보를 이용해서 토큰을 생성하는 createToken 메소드
     */

    //1번 : authentication 파라미터를 받고
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        //2번 : application yml 에 작성했던 만료시간을 설정
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds);

        //3번 : jwt 토큰을 생성해서 리턴
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }


    /**
     *  Token에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메소드 생성하는법
     */

    //1번 : 토큰을 이용해서 클렝미을 만듬
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        //2번 : 클레임에서 권한 정보를 빼냄냄
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        //3번 : 빼낸 권한정보를 이용해 유저 객체를 만듬
        User principal = new User(claims.getSubject(), "", authorities);


        //4번 : 유저 객체, 토큰, 권한 정보를 바탕으로 Authentication 객체를 리턴한다
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }


    /**
     * 토큰을 파라미터로 받아 토큰의 유효성 검증을 수행하는 매서드
     */
    public boolean validateToken(String token) {
        try { //토큰을 받아 파싱하고 발생하는 exception을 캐치함 -> true , false 로 반환
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}