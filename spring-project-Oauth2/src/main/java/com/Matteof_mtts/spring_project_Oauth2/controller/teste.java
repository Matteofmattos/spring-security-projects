package com.Matteof_mtts.spring_project_Oauth2.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/home")
public class teste {

    @GetMapping
    public String getHello(){
        return "hello";
    }
}
