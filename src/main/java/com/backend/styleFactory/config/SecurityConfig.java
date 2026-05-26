package com.backend.styleFactory.config;

import com.backend.styleFactory.security.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtFilter jwtFilter;
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfig(JwtFilter jwtFilter,
                          AuthenticationProvider authenticationProvider) {
        this.jwtFilter = jwtFilter;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configure(http))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Swagger: público durante desarrollo
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-ui.html"
                        ).permitAll()
                        // Auth: público — login y registro
                        .requestMatchers("/api/auth/**").permitAll()
                        // Registro de usuario: público
                        .requestMatchers(HttpMethod.POST, "/api/usuarios").permitAll()

                        // Usuarios: solo ADMIN
                        .requestMatchers(HttpMethod.GET, "/api/usuarios/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/usuarios/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/usuarios/**").hasRole("ADMIN")

                        // Servicios: GET público, modificaciones solo ADMIN
                        .requestMatchers(HttpMethod.GET, "/api/servicios/**").hasAnyRole("ADMIN", "EMPLEADO", "CLIENTE")
                        .requestMatchers(HttpMethod.POST, "/api/servicios/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/servicios/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/servicios/**").hasRole("ADMIN")

                        // Empleados: ADMIN gestiona, CLIENTE puede ver
                        .requestMatchers(HttpMethod.GET, "/api/empleados/**").hasAnyRole("ADMIN", "CLIENTE")
                        .requestMatchers(HttpMethod.POST, "/api/empleados/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/empleados/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/empleados/**").hasRole("ADMIN")

                        // Reservas: ADMIN y CLIENTE pueden crear y ver
                        .requestMatchers(HttpMethod.GET, "/api/reservas/**").hasAnyRole("ADMIN", "CLIENTE")
                        .requestMatchers(HttpMethod.POST, "/api/reservas/**").hasAnyRole("ADMIN", "CLIENTE")
                        .requestMatchers(HttpMethod.PUT, "/api/reservas/**").hasAnyRole("ADMIN", "EMPLEADO")
                        .requestMatchers(HttpMethod.DELETE, "/api/reservas/**").hasRole("ADMIN")

                        // Horarios: ADMIN y EMPLEADO
                        .requestMatchers(HttpMethod.GET, "/api/horarios/**").hasAnyRole("ADMIN", "EMPLEADO", "CLIENTE")
                        .requestMatchers(HttpMethod.POST, "/api/horarios/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/horarios/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/horarios/**").hasRole("ADMIN")

                        // Todo lo demás requiere autenticación
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
