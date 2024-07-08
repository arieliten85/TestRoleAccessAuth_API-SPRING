package com.app.service;


import com.app.controller.dto.AuthCreateUserRequest;
import com.app.controller.dto.AuthLoginRequest;
import com.app.controller.dto.AuthResponse;
import com.app.persistence.entity.RoleEntity;
import com.app.persistence.entity.UserEntity;
import com.app.persistence.repository.RoleRepository;
import com.app.persistence.repository.UserRepository;
import com.app.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired

    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("User " + username + " does not exist."));


        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        userEntity.getRoles()
                .forEach(role -> authorityList.add(new SimpleGrantedAuthority(("ROLE_".concat(role.getRoleEnum().name())))));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permmission -> authorityList.add(new SimpleGrantedAuthority(permmission.getName())));


        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnabled(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),

                authorityList);

    }

    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();
        try {
            Authentication authentication = this.authenticate(username, password);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.createToken(authentication);
            return new AuthResponse(username, "User longed successfully", accessToken, true);
        } catch (BadCredentialsException | UsernameNotFoundException e) {
            return new AuthResponse(username, e.getMessage(), null, false);
        }


    }

    public AuthResponse createUser(AuthCreateUserRequest authCreateUserRequest) {

        String username = authCreateUserRequest.username();
        String password = authCreateUserRequest.password();

        if (userRepository.findUserEntityByUsername(username).isPresent()) {
            return new AuthResponse(username, "User already exists", null, false);
        }
        // CAPTURE EL ROLE, Ej ADMIN
        List<String> rolesRequest = authCreateUserRequest.roleRequest().roleListName();
        Set<RoleEntity> FoundPermissionsList = new HashSet<>(roleRepository.findRoleEntitiesByRoleEnumIn(rolesRequest));

        if (FoundPermissionsList.isEmpty()) {
            throw new IllegalArgumentException("The roles specified do not exist.");
        }
        UserEntity userEntity = UserEntity.builder().username(username).password(passwordEncoder.encode(password)).roles(FoundPermissionsList).isEnabled(true).accountNoLocked(true).accountNoExpired(true).credentialNoExpired(true).build();
        UserEntity userSaved = userRepository.save(userEntity);
        ArrayList<SimpleGrantedAuthority> authorities = new ArrayList<>();
        userSaved.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));
        userSaved.getRoles().stream().flatMap(role -> role.getPermissionList().stream()).forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission.getName())));
        SecurityContext securityContextHolder = SecurityContextHolder.getContext();
        Authentication authentication = new UsernamePasswordAuthenticationToken(userSaved, null, authorities);
        String accessToken = jwtUtils.createToken(authentication);
        return new AuthResponse(username, "User created successfully", accessToken, true);
    }

    public Authentication authenticate(String username, String password) {
        UserDetails userDetails = this.loadUserByUsername(username);
        if (userDetails == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Incorrect Password");
        }


        return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
    }


}
