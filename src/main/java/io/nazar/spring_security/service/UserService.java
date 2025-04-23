package io.nazar.spring_security.service;

import io.nazar.spring_security.controller.model.AuthenticationRequest;
import io.nazar.spring_security.controller.model.AuthenticationResponse;
import io.nazar.spring_security.controller.model.RegisterRequest;
import io.nazar.spring_security.model.User;
import io.nazar.spring_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public AuthenticationResponse registerUser(RegisterRequest request) {
    User user = new User();

    user.setFirstname(request.getFirstname());
    user.setLastname(request.getLastname());
    user.setUsername(request.getUsername());
    user.setEmail(request.getEmail());
    user.setPassword(encoder.encode(request.getPassword()));

    userRepository.save(user);

    String token = jwtService.generateToken(user.getUsername());

    AuthenticationResponse authenticationResponse = new AuthenticationResponse();
    authenticationResponse.setToken(token);

    return authenticationResponse;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
                );
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        String token = jwtService.generateToken(user.getUsername());
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setToken(token);
        return authenticationResponse;
    }
}
