package io.github.henriquediascampos.authorizationserver.controller;

import java.util.List;

import javax.websocket.server.PathParam;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.github.henriquediascampos.authorizationserver.entity.UserEntity;
import io.github.henriquediascampos.authorizationserver.service.UserRepository;

@RestController
@RequestMapping("user")
public class UserController {
    @Autowired private UserRepository repository;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public List<UserEntity> list() {
        return repository.findAll();
    }

    @GetMapping("/{id}")
    @ResponseStatus(HttpStatus.OK)
    public UserEntity findbyId(@PathParam("id") final Long id) {
        return repository.findById(id).orElseThrow( () -> new UsernameNotFoundException("Usuário não encontrado!"));
    }


    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public UserEntity save(@PathParam("id") final UserEntity user) {
        return repository.save(user);
    }

    @GetMapping("teste")
    @ResponseStatus(HttpStatus.CREATED)
    // @PreAuthorize("hasRole('ROLE_ADMIN')")

    public UserEntity teste(@AuthenticationPrincipal Jwt jwt) {
        return repository.findByEmail(jwt.getClaims().get("sub").toString()).orElseThrow();
    }
}
