
import static java.lang.StrictMath.*;

import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyAgreementClient {
	private BigInteger public_key, private_key;
	public BigInteger getPublic_key() {
		return public_key;
	}

	public BigInteger getPrivate_key() {
		return private_key;
	}

	public int getPrime_number() {
		return prime_number;
	}

	public int getGenerator() {
		return generator;
	}

	private int prime_number, generator;
	
	public KeyAgreementClient(int prime, int gen) {
		this.public_key = BigInteger.valueOf(0);
		do {
		this.private_key = GetSecure.randomNumber();
		}while(this.private_key.intValue() ==1 || this.private_key.intValue() == 0);
		this.prime_number = prime;
		this.generator = gen;
	}
	
	void calculate_public_key() {
		
		this.public_key = BigInteger.valueOf(generator).pow(private_key.intValue()).mod(BigInteger.valueOf(prime_number));
	}
	
	BigInteger derive_shared_key(BigInteger other_public_key) {
		System.out.println("Other Public Key: " + other_public_key);
		System.out.println("Private Key: " + this.private_key);
		System.out.println("Prime Key: " + prime_number);
		return other_public_key.pow(private_key.intValue()).mod(BigInteger.valueOf(prime_number));
	}
	
	
	
}
