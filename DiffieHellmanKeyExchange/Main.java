import java.math.BigInteger;

public class Main {

	public static void main(String[] args) {
		int P = 523;
		int g = 7;
		
		System.out.println("\nThe clients have agreed to use the following: \n\tPrime number: " + P + " Generator: " + g);
		
		KeyAgreementClient clientA = new KeyAgreementClient(P, g);
		KeyAgreementClient clientB = new KeyAgreementClient(P, g);
		
		System.out.println("\nClient A chose a random number: \n\t" + clientA.getPrivate_key() + "\nClient B chose a random number: \n\t" + clientB.getPrivate_key());
		
		clientA.calculate_public_key();
		clientB.calculate_public_key();
		
		System.out.println("\nClient A's public key is: \n\t" + clientA.getPublic_key() + "\nClient B's public key is: \n\t" + clientB.getPublic_key());
		
		BigInteger clientA_Secret = clientA.derive_shared_key(clientB.getPublic_key());
		BigInteger clientB_Secret = clientB.derive_shared_key(clientA.getPublic_key());
		
		System.out.println("\nClient A's derived shared secret: \n\t" + clientA_Secret + "\nClient B's derived shared secret: \n\t" + clientB_Secret);
		
		System.out.println("\nClient A's derived encryption key: \n\t" + GetSecure.encryption_key(clientA_Secret) + "\nClient B's derived encryption key: \n\t" + GetSecure.encryption_key(clientB_Secret));
		
	}

}
