package co.edu.uni.acme.ariline.server.authorization;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.core.env.Environment;

import java.util.Arrays;

@SpringBootApplication
@EntityScan(basePackages = {"co.edu.uni.acme.aerolinea.commons.entity", "co.edu.uni.acme.ariline.server.authorization"})
public class AuthorizationApplication {

	@Autowired
	private Environment environment;

	public static void main(String[] args) {
		new SpringApplicationBuilder(AuthorizationApplication.class)
				.properties("spring.config.name=application")
				.properties("spring.config.location=classpath:/application.yaml") // <-- Aquí forzas que use solo ese
				.run(args);
	}

}
