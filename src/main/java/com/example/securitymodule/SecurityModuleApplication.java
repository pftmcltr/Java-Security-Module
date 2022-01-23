package com.example.securitymodule;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.File;

import static com.example.securitymodule.constant.FileConstant.USER_FOLDER;

@SpringBootApplication
public class SecurityModuleApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityModuleApplication.class, args);

		new File(USER_FOLDER).mkdirs(); // Create a user folder when application runs.
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder(){
		return new BCryptPasswordEncoder();
	}

}
