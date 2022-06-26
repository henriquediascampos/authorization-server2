package io.github.henriquediascampos.authorizationserver.core;

import java.time.OffsetDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import io.github.henriquediascampos.authorizationserver.entity.ETypeUser;
import io.github.henriquediascampos.authorizationserver.entity.UserEntity;
import io.github.henriquediascampos.authorizationserver.service.UserRepository;

@Component
public class FirstUserConfig implements ApplicationRunner {

	private final Logger logger = LoggerFactory.getLogger(FirstUserConfig.class);
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public FirstUserConfig(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {
		if (userRepository.count() != 0) {
			return;
		}

		logger.info("Nenhum usuário encontrado, cadastrando usuários padrão.");

		userRepository.save(
				UserEntity.builder()
                .name("Henrique Dias")
                .email("admin@email.com")
                .password(passwordEncoder.encode("123456"))
                .type(ETypeUser.ADMIN)
                .createdAt(OffsetDateTime.now())
                .build()
		);

		userRepository.save(
            UserEntity.builder()
                .name("Henrique Dias")
                .email("henrique@email.com")
                .password(passwordEncoder.encode("123456"))
                .type(ETypeUser.USER)
                .createdAt(OffsetDateTime.now())
                .build()
		);
	}
}