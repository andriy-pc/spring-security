package org.mota.jwtdemo.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * <a
 * href="https://github.com/koushikkothagal/spring-security-jwt/blob/master/src/main/java/io/javabrains/springsecurityjwt/util/JwtUtil.java">Resource</a>
 */
@Profile("jwt-old")
public class JwtUtils {

  private JwtUtils() {

  }

  public static final String SECRET_KEY = "02uC0D7Yw1z4tVquxeq6lUjIUrXK+G02Y4fyax1FMe0=";
  private static final Date TOKEN_EXPIRATION_DATE = new Date(
      System.currentTimeMillis() + 1000 * 60 * 60 * 10);
  private static final Date REFRESH_TOKEN_EXPIRATION_DATE = new Date(
      System.currentTimeMillis() + 1000 * 60 * 60 * 10);

  public static String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public static Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public static <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private static Claims extractAllClaims(String token) {
    return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
  }

  private static Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public static String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return createToken(claims, userDetails.getUsername(), TOKEN_EXPIRATION_DATE);
  }

  public static String generateRefreshToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return createToken(claims, userDetails.getUsername(), REFRESH_TOKEN_EXPIRATION_DATE);
  }

  private static String createToken(Map<String, Object> claims, String subject, Date expDate) {

    return Jwts.builder().setClaims(claims).setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(expDate)
        .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
  }

  public static Boolean validateToken(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }
}