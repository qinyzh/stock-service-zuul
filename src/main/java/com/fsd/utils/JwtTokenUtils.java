package com.fsd.utils;

import java.util.Date;
import java.util.HashMap;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtTokenUtils {

    public static final String TOKEN_HEADER = "X-Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private static final String SECRET = "QyzFsdJwtSecret";
    private static final String ISS = "FSD Qyz";

    // expiration time is 3600s(1hour)
    private static final long EXPIRATION = 3600L;
    //private static final long EXPIRATION = 60;
    private static final String ROLE_CLAIMS = "rol";

    // after choosing remember me,expiration time is 7days
    private static final long EXPIRATION_REMEMBER = 604800L;

    // create token
    public static String createToken(String username,String usertype, boolean isRememberMe) {
        long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;
        HashMap<String, Object> map = new HashMap<>();
        map.put(ROLE_CLAIMS, usertype);//0:admin;1:user;
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .setClaims(map)
                .setIssuer(ISS) //jwt issuser
                .setSubject(username)//jwt user
                .setIssuedAt(new Date()) //jwt issue date
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000)) 
                .compact();
    }

    /**
     * Get user name from token body
     * @param token
     * @return
     */
    public static String getUsername(String token){
        return getTokenBody(token).getSubject();
    }
    
    /**
     * Get user type from token body
     * @param token
     * @return
     */
    public static String getUserRole(String token){
        return (String) getTokenBody(token).get(ROLE_CLAIMS);
    }

    /**
     * Determine if it is expired
     * @param token
     * @return
     */
    public static boolean isExpiration(String token){
        return getTokenBody(token).getExpiration().before(new Date());
    }

    /**
     * Get payload from token
     * @param token
     * @return
     */
    private static Claims getTokenBody(String token){
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}

