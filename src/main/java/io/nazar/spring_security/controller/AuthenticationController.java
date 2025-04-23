package io.nazar.spring_security.controller;

import io.nazar.spring_security.controller.model.AuthenticationRequest;
import io.nazar.spring_security.controller.model.AuthenticationResponse;
import io.nazar.spring_security.controller.model.RegisterRequest;
import io.nazar.spring_security.model.User;
import io.nazar.spring_security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register (@RequestBody RegisterRequest request) {
    return ResponseEntity.ok(userService.registerUser(request));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> register (@RequestBody AuthenticationRequest request) {
    return ResponseEntity.ok(userService.authenticate(request));
    }
}
