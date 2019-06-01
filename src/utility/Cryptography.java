package utility;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class Cryptography {

	public static long genNonce(SecureRandom sr) {
		int size = Long.BYTES + 1;
		byte[] tmp = new byte[size];
		sr.nextBytes(tmp);

		ByteBuffer buffer = ByteBuffer.wrap(tmp);
		return buffer.getLong();
	}

	public static PublicKey parsePublicKey(String publicKey, KeyFactory kf) throws InvalidKeySpecException {
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(publicKey));
		return kf.generatePublic(keySpecX509);
	}

	public static String encodePublicKey(PublicKey publicKey) {
		return java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}

	public static String encodePrivateKey(PrivateKey privateKey) {
		return java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded());
	}

	public static PrivateKey parsePrivateKey(String privateKey, KeyFactory kf) throws InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(privateKey));
		return kf.generatePrivate(keySpecPKCS8);
	}

	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		return buildCipher(cipherAlgorithm, cipherMode, key, null, null);
	}

	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		return buildCipher(cipherAlgorithm, cipherMode, key, iv, null);
	}

	public static Cipher buildCipher(String cipherAlgorithm, int cipherMode, SecretKey key, byte[] iv, String provider)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {

		Cipher cipher = null;
		if(provider == null || provider.equals(""))
			cipher = Cipher.getInstance(cipherAlgorithm);
		else
			cipher = Cipher.getInstance(cipherAlgorithm, provider);

		if (iv != null && iv.length > 0) {
			cipher.init(cipherMode, key, new IvParameterSpec(iv));
		} else
			cipher.init(cipherMode, key);

		return cipher;
	}

	public static byte[] encrypt(Cipher encryptCipher, byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
	InvalidAlgorithmParameterException, ShortBufferException {

		byte[] cipherText = new byte[encryptCipher.getOutputSize(plaintext.length)];
		int ctLength = encryptCipher.update(plaintext, 0, plaintext.length, cipherText, 0);
		ctLength += encryptCipher.doFinal(cipherText, ctLength);	

		return cipherText;
	}

	public static byte[] decrypt(Cipher decryptCipher, byte[] cipherText)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

		byte[] plainText = new byte[decryptCipher.getOutputSize(cipherText.length)];
		int ptLength = decryptCipher.update(cipherText, 0, cipherText.length, plainText, 0);
		ptLength += decryptCipher.doFinal(plainText, ptLength);

		return Arrays.copyOfRange(plainText, 0, ptLength);
	}

	public static byte[] digest(MessageDigest hash_function, byte[] data) {
		hash_function.reset();
		hash_function.update(data);
		return hash_function.digest();
	}

	public static byte[] sign(Signature signature, PrivateKey privKey, byte[] data) throws SignatureException, InvalidKeyException {
		signature.initSign(privKey, new SecureRandom());
		signature.update(data);

		return signature.sign();
	}
	
	public static boolean validateSignature(Signature signature, PublicKey pubKey, byte[] data, byte[] sig) throws SignatureException, InvalidKeyException {
		signature.initVerify(pubKey);
        signature.update(data);

        return signature.verify(sig);
	}

	public static Cipher[] genPBECiphers(String password, byte[] salt, int iterations, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException {
     
        PBEKeySpec          pbeSpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory    keyFact = SecretKeyFactory.getInstance(algorithm, provider);
        Key sKey= keyFact.generateSecret(pbeSpec);

        Cipher cEnc = Cipher.getInstance(algorithm,provider);
        cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterations));
       
        Cipher cDec = Cipher.getInstance(algorithm,provider);
        cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterations));
        
        return new Cipher[] {cEnc, cDec};
	}
	
	public static byte[] createIV(int blockSize) {
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[blockSize];
		randomSecureRandom.nextBytes(iv);
		return iv;
	}
	
}
