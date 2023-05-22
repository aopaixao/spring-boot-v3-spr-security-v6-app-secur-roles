package br.com.residencia.seguranca.security.jwt;

import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import br.com.residencia.seguranca.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	@Value("${app.jwt.secret}")
	private String jwtSecret;

	@Value("${app.jwt.expiration.ms}")
	private int jwtExpirationMs;
	
	private Key jwtKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

	public String generateJwtToken(Authentication authentication) {

		UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
		Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
		/*
		Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwtSecret), 
                SignatureAlgorithm.HS256.getJcaName());
        */
		SecretKey sKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
		
		return Jwts.builder()
					.setSubject((userPrincipal.getUsername()))
					.setIssuedAt(new Date())
					.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
					.signWith(sKey)
					//.signWith(hmacKey)
					//.signWith(sKey, SignatureAlgorithm.HS512)
					//.encryptWith(jwtSecret, key , "HS256")
					.compact();
	}

	public String getUserNameFromJwtToken(String token) {
		//Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
		Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwtSecret), 
                SignatureAlgorithm.HS512.getJcaName());
		SecretKey sKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
		return Jwts.parserBuilder()
				//.setSigningKey(hmacKey)
				.setSigningKey(sKey)
				//.setSigningKey(jwtKey)
				.build()
				.parseClaimsJws(token)
				.getBody().getSubject();
	}

	public boolean validateJwtToken(String authToken) {
		try {
			//Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
			SecretKey sKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
			Jwts.parserBuilder()
				.setSigningKey(sKey)
				.build()
				.parseClaimsJws(authToken)
				.getBody()
				.getSubject();
			return true;
		}catch (JwtException e) {
			logger.error("Token JWT inválido: {}", e.getMessage());
		}
		return false;
	}
}