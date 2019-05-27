package fServer.authServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import rest.client.RestResponse;
import rest.client.mySecureRestClient;
import utility.Cryptography;

public class AuthenticationClient {
	
	public static RestResponse get_requestSession(mySecureRestClient client, String resource_path, String username) throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {
		return client.newRequest(resource_path).addPathParam("requestSession")
				.addPathParam(username).get();
	}
	
	public static SessionEstablishmentParameters requestSession(mySecureRestClient client, String resource_path, String username) throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {
		
		RestResponse response = get_requestSession(client, resource_path, username);

		if (response.getStatusCode() == 200) {
			return (SessionEstablishmentParameters) response.getEntity(SessionEstablishmentParameters.class);
		} else if (response.getStatusCode() == 403) {
			String message = (String) response.getEntity(String.class);
			throw new DeniedAccessException(message);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}

	public static RestResponse post_requestToken(mySecureRestClient client, String resource_path, String username, String user_public_value, long client_nonce, byte[] credentials)
			throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {
		return client.newRequest(resource_path).addPathParam("requestToken")
				.addPathParam(username).addPathParam(user_public_value).addQueryParam("client_nonce", "" + client_nonce)
				.post(credentials);
	}
	
	public static byte[] requestToken(mySecureRestClient client, String resource_path, String username, String user_public_value, long client_nonce, byte[] credentials)
			throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {
		
		RestResponse response = post_requestToken(client, resource_path, username, user_public_value, client_nonce, credentials);

		if (response.getStatusCode() == 200) {
			return (byte[]) response.getEntity(byte[].class);
		} else if (response.getStatusCode() == 403) {
			String message = (String) response.getEntity(String.class);
			throw new DeniedAccessException(message);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}

	public static AuthenticationToken login(mySecureRestClient client, String resource_path, String username, String password, MessageDigest hash, byte[] raw_iv)
			throws UnsupportedEncodingException, UnknownHostException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, ExpiredTokenException, WrongChallengeAnswerException,
			NoSuchPaddingException, DeniedAccessException, InvalidKeySpecException {

		// Request a session
		SessionEstablishmentParameters msg1 = requestSession(client, resource_path, username);

		// Establish a shared key
		SecureRandom sr = SecureRandom.getInstance(msg1.getSecure_random_algorithm());

		DiffieHellman dh_local = new DiffieHellman(msg1.getP(), msg1.getG(), msg1.getSecret_key_size(),
				msg1.getSecret_key_algorithm(), msg1.getProvider(), sr);

		KeyPair myKeyPair = dh_local.genKeyPair();
		PublicKey server_pub_key = Cryptography.parsePublicKey(msg1.getPublic_value(), dh_local.getKeyFactory());
		SecretKey ks = dh_local.establishSecretKey(myKeyPair.getPrivate(), server_pub_key);

		// Transform the password
		byte[] p_hash = Cryptography.digest(hash, password.getBytes());

		IvParameterSpec iv = new IvParameterSpec(raw_iv);
		Cipher cipher = Cipher.getInstance(msg1.getEncryption_algorithm());
		cipher.init(Cipher.ENCRYPT_MODE, ks, iv);

		byte[] credentials = buildCredentials(p_hash, msg1.getNonce() + 1, cipher);

		String user_public_value = Cryptography.encodePublicKey(myKeyPair.getPublic());
		long client_nonce = Cryptography.genNonce(sr);

		// Request the authentication token
		byte[] msg2 = requestToken(client, resource_path, username, user_public_value, client_nonce, credentials);

		// Decrypt message and retrieve the token
		cipher.init(Cipher.DECRYPT_MODE, ks, iv);
		return retrieveToken(msg2, client_nonce + 1, cipher);
	}

	private static AuthenticationToken retrieveToken(byte[] msg2, long client_challenge_answer, Cipher cipher)
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			IOException, ExpiredTokenException, WrongChallengeAnswerException {
		byte[] raw = Cryptography.decrypt(cipher, msg2);

		ByteArrayInputStream byteIn = new ByteArrayInputStream(raw);
		DataInputStream dataIn = new DataInputStream(byteIn);

		int token_size = dataIn.readInt();
		byte[] raw_token = new byte[token_size];
		dataIn.read(raw_token, 0, token_size);

		long challenge_answer = dataIn.readLong();

		dataIn.close();
		byteIn.close();

		if (client_challenge_answer == challenge_answer) {
			AuthenticationToken token = AuthenticationToken.parseToken(raw_token);

			if (!token.isExpired(System.currentTimeMillis()))
				return token;
			else
				throw new ExpiredTokenException();
		} else {
			throw new WrongChallengeAnswerException();
		}

	}

	private static byte[] buildCredentials(byte[] p_hash, long challenge_answer, Cipher cipher)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeInt(p_hash.length);
		dataOut.write(p_hash);
		dataOut.writeLong(challenge_answer);

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		byte[] credentials = Cryptography.encrypt(cipher, msg);

		dataOut.close();
		byteOut.close();

		return credentials;
	}
}
