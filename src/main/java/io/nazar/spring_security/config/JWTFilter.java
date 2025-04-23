package io.nazar.spring_security.config;

import io.nazar.spring_security.service.JWTService;
import io.nazar.spring_security.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;
    @Autowired // Si da problemas usar ApplicationContext
    private MyUserDetailsService myUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    String authorizationHeader = request.getHeader("Authorization");
    String token = null;
    String username = null;

    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
        token = authorizationHeader.substring(7);
        username = jwtService.extractUsername(token);
    }
    if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
        if(jwtService.isTokenValid(token, userDetails)) {
            // Agregamos el siguiente filtro
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
    }
    filterChain.doFilter(request, response);
}
}
