package com.JWTjavaa.JWTjava;

import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import java.util.Base64;

@SpringBootApplication
public class JwTjavaApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwTjavaApplication.class, args);
	}
	public class GenerateJwtKey {
		public static void main(String[] args) {
			// Generate a new SecretKey for HS384
			SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS384);

			// Encode the key in Base64 to make it suitable for configuration
			String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());

			// Print the key to use it in your configuration
			System.out.println("Generated Key: " + base64Key);
		}
	}
}
