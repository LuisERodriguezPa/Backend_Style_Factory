package com.backend.styleFactory.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    // Genera el token recibiendo UserDetails
    public String generarToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("rol", userDetails.getAuthorities()
                .iterator().next().getAuthority());
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    // Extrae el correo del token
    public String extraerCorreo(String token) {
        return getClaims(token).getSubject();
    }

    // Extrae el rol del token
    public String extraerRol(String token) {
        return getClaims(token).get("rol", String.class);
    }

    // Valida si el token corresponde al usuario y no ha expirado
    public boolean validarToken(String token, UserDetails userDetails) {
        String correo = extraerCorreo(token);
        return correo.equals(userDetails.getUsername()) && !tokenExpirado(token);
    }

    // Métodos privados
    private boolean tokenExpirado(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Usa la misma lógica del compañero — convierte hex a bytes
    private SecretKey getSigningKey() {
        byte[] keyBytes = hexToBytes(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private byte[] hexToBytes(String hex) {
        int length = hex.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }
}