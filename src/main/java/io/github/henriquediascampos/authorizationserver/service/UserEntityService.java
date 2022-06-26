package io.github.henriquediascampos.authorizationserver.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserEntityService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserEntityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        final var user = userRepository.findByEmail(email).orElseThrow(()-> new UsernameNotFoundException(email));

        final var simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_"+user.getType().name());

        var userDetails = new User(
                user.getEmail(),
                user.getPassword(),
                List.of(simpleGrantedAuthority)
        );

        return userDetails;
    }

}