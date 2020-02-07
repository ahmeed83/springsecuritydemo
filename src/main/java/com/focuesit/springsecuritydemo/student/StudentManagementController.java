package com.focuesit.springsecuritydemo.student;

import java.util.Arrays;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

  private static final List<Student> STUDENTS = Arrays.asList(
      new Student(1, "Ahmed"),
      new Student(2, "Hayder"),
      new Student(3, "Nassar")
  );

  //hasRole('ROLE_') hasANyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('Permission')

  @GetMapping
  @PreAuthorize("hasAnyRole('ROLE_ADMIN, ROLE_ADMINTRAINEE')")
  public List<Student> getAllStudents() {
    return STUDENTS;
  }

  @PostMapping
  @PreAuthorize("hasAuthority('student:write')")
  public void registerNewStudent(@RequestBody Student student) {
    System.out.println("Student created with is:" + student);
  }

  @DeleteMapping(path = "{studentId}")
  @PreAuthorize("hasAuthority('student:write')")
  public void deleteStudent(@PathVariable Integer studentId) {
    System.out.println("Student deleted with id:" + studentId);
  }

  @PutMapping(path = "{studentId}")
  @PreAuthorize("hasAuthority('student:write')")
  public void updateStudent(@PathVariable Integer studentId, @RequestBody Student student) {
    System.out.println(String.format("Student id updated is: %s for Student: %s", studentId, student));
  }
}
