package com.javaboy.security_jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }
    @GetMapping("/admin/hello")
    public String admin(){
        return "hello admin";
    }
}
