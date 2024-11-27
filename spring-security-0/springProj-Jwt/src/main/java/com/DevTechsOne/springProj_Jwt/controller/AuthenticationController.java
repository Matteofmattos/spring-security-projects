package com.DevTechsOne.springProj_Jwt.controller;

import com.DevTechsOne.springProj_Jwt.config.AuthenticationRequest;
import com.DevTechsOne.springProj_Jwt.config.AuthenticationResponse;
import com.DevTechsOne.springProj_Jwt.config.AuthenticationService;
import com.DevTechsOne.springProj_Jwt.entities.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register( @RequestBody User user){

        return ResponseEntity.ok(authenticationService.register(user));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.login(request));
    }

}
