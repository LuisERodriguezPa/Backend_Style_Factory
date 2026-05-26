package com.backend.styleFactory.security;

import com.backend.styleFactory.repository.UsuarioRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UsuarioRepository usuarioRepository;

    public JwtFilter(JwtUtil jwtUtil, UsuarioRepository usuarioRepository) {
        this.jwtUtil = jwtUtil;
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Leer el header Authorization
        final String authHeader = request.getHeader("Authorization");

        // Si no tiene token pasar al siguiente filtro
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extraer el token removiendo "Bearer "
        final String token = authHeader.substring(7);

        // Extraer el correo del token
        final String correo = jwtUtil.extraerCorreo(token);

        // Solo proceder si tenemos correo y el usuario no está autenticado
        if (correo != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Cargar el usuario desde la BD usando findByCorreo
            UserDetails userDetails = usuarioRepository
                    .findByCorreo(correo)
                    .map(u -> (UserDetails) u)
                    .orElse(null);

            // Validar que el usuario existe y el token es válido
            if (userDetails != null && jwtUtil.validarToken(token, userDetails)) {

                // Crear el objeto de autenticación
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                // Agregar detalles de la solicitud
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Registrar autenticación en el SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Continuar con el siguiente filtro
        filterChain.doFilter(request, response);
    }
}