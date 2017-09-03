
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

public class GetSecure {
	public static BigInteger randomNumber() {
		int maxValue = 2 ^ 10;
		BigInteger intermediateInt = BigInteger.valueOf(0);
		
			byte[] random_seed = new byte[maxValue];
			try {
				SecureRandom.getInstance("SHA1PRNG").nextBytes(random_seed);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}

			intermediateInt = BigInteger.valueOf(java.nio.ByteBuffer.wrap(random_seed).getInt());

			//intermediateInt = new BigInteger(maxValue, sr);
		
			if(intermediateInt.intValue() < 0) {
				intermediateInt.multiply(BigInteger.valueOf(-1));
			}
			
		return intermediateInt.mod(BigInteger.valueOf(10));
	}
	
	public static String encryption_key(BigInteger clientA_Secret) {
		String generatedPassword = null;
		BigInteger iterations = BigInteger.valueOf(2^18);
		byte[] bytes = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			bytes = md.digest(clientA_Secret.toString().getBytes("UTF-8"));
			for(int i =0; i<iterations.intValue(); i++) {
				md.update(bytes);
				bytes = md.digest();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String encryption_key = Base64.getEncoder().encodeToString(bytes);
		
		return encryption_key;
	}

	public static String get_SHA_512_SecurePassword(String passwordToHash, String salt) {
		String generatedPassword = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(salt.getBytes("UTF-8"));
			byte[] bytes = md.digest(passwordToHash.getBytes("UTF-8"));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return generatedPassword;
	}
}
