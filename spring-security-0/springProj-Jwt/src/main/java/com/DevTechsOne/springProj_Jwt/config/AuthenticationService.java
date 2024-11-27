package com.DevTechsOne.springProj_Jwt.config;

import com.DevTechsOne.springProj_Jwt.entities.User;
import com.DevTechsOne.springProj_Jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenticationService {

    @Autowired
    private JwtService jwtService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public AuthenticationService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    public AuthenticationResponse login(AuthenticationRequest request){

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword());

        authenticationManager.authenticate(authentication); //Generate the Authentication and set it in the context;

        User user = userRepository.findByUsername(request.getUsername()).get();

        String jwt = jwtService.generateToken(user,getExtraClaims(user));

        return new AuthenticationResponse(jwt);

    }

    public AuthenticationResponse register(User request){

        var user = new User();
        user.setName(request.getName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());

        userRepository.save(user);

        String token = jwtService.generateToken(user, getExtraClaims(user));

        return  new AuthenticationResponse(token);
    }



    private Map<String, Object> getExtraClaims(User user) {

        Map<String,Object> extraClaims = new HashMap<>();

        extraClaims.put("username",user.getUsername());
        extraClaims.put("role",user.getRole().name());

        return extraClaims;
    }
}
