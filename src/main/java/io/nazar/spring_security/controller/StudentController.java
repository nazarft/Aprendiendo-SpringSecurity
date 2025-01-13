package io.nazar.spring_security.controller;

import io.nazar.spring_security.model.Student;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/students")
public class StudentController {
    List<Student> students = new ArrayList<>(List.of(
            new Student(1, "Alice", 100),
            new Student(2, "Bob", 90),
            new Student(3, "Charlie", 80)
    ));
    @GetMapping
    public List<Student> getStudents() {
        return students;
    }
    @PostMapping
    public Student addStudent(@RequestBody Student student) {
        students.add(student);
        return student;
    }
    @GetMapping("/csrf-token")
    public CsrfToken getCsrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");
    }
}
