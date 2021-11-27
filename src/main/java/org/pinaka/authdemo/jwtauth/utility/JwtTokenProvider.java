package org.pinaka.authdemo.jwtauth.utility;

import static java.util.Arrays.stream;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.pinaka.authdemo.jwtauth.constants.SecurityConstant;
import org.pinaka.authdemo.jwtauth.model.UserPrincipal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;

@Component
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secret;

	// Generate token for the correctly verified user
	public String generateJwtToken(UserPrincipal userPrincipal) {
		String[] claims = getClaimsFromUser(userPrincipal);
		return JWT.create().withIssuer(SecurityConstant.GET_ARRAYS_LLC)
				.withAudience(SecurityConstant.GET_ARRAYS_ADMINSTRATION).withIssuedAt(new Date())
				.withSubject(userPrincipal.getUsername()).withArrayClaim(SecurityConstant.AUTHORITIES, claims)
				.withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstant.EXPIRATION_TIME))
				.sign(Algorithm.HMAC512(secret.getBytes()));
	}

	// get authorities from the receied token
	public List<GrantedAuthority> getAuthorities(String token) {
		String claims[] = getClaimsFromToken(token);
		return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	// for valid tokens get the authenticity of user
	public Authentication getAuthentication(String username, List<GrantedAuthority> authorities,
			HttpServletRequest request) {
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				username, null, authorities);
		usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		return usernamePasswordAuthenticationToken;
	}

	// check for token validity
	public boolean isTokenValid(String userName, String token) {
		JWTVerifier verfier = getJWTVerifier();
		return StringUtils.isNotEmpty(userName) && !isTokenExpired(verfier, token);
	}

	// get subject
	public String getSubject(String token) {
		JWTVerifier verfier = getJWTVerifier();

		return verfier.verify(token).getSubject();
	}

	private boolean isTokenExpired(JWTVerifier verfier, String token) {
		Date expirationDate = verfier.verify(token).getExpiresAt();
		return expirationDate.before(new Date());
	}

	private String[] getClaimsFromToken(String token) {
		JWTVerifier verfier = getJWTVerifier();
		return verfier.verify(token).getClaim(SecurityConstant.AUTHORITIES).asArray(String.class);
	}

	private JWTVerifier getJWTVerifier() {
		JWTVerifier verifier;
		try {
			Algorithm algorithm = Algorithm.HMAC512(secret);
			verifier = JWT.require(algorithm).withIssuer(SecurityConstant.GET_ARRAYS_LLC).build();

		} catch (JWTVerificationException ex) {
			throw new JWTVerificationException(SecurityConstant.TOKEN_CANNOT_BE_VERIFIED);
		}
		return verifier;
	}

	private String[] getClaimsFromUser(UserPrincipal user) {
		List<String> authorities = new ArrayList<>();
		for (GrantedAuthority grantedAuthority : user.getAuthorities()) {
			authorities.add(grantedAuthority.getAuthority());
		}
		return authorities.toArray(new String[0]);
	}
}
