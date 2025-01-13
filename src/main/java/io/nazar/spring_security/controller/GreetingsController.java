package io.nazar.spring_security.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/greetings")
public class GreetingsController {
        @GetMapping
        public ResponseEntity<String> sayHello(HttpServletRequest request) {
            return ResponseEntity.ok("Hello, World! " + request.getSession().getId());
        }
    @GetMapping("/bye")
    public ResponseEntity<String> sayGoodbye() {
        return ResponseEntity.ok("Goodbye, World!");
    }
}
