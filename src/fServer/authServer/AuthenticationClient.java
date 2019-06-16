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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import rest.RestResponse;
import rest.client.mySecureRestClient;
import token.ExpiredTokenException;
import token.auth.AuthenticationToken;
import utility.Cryptography;
import utility.LoginUtility;

public class AuthenticationClient {

	public static RestResponse get_requestSession(mySecureRestClient client, String resource_path, String username) throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {
		return client.newRequest(resource_path)
				.addPathParam("requestSession")
				.addPathParam(username)
				.get();
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

	public static RestResponse post_requestToken(mySecureRestClient client, String resource_path, String username, long client_nonce, byte[] credentials)
			throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {
		return client.newRequest(resource_path).addPathParam("requestToken")
				.addPathParam(username).addQueryParam("client_nonce", "" + client_nonce)
				.post(credentials);
	}

	public static EnvelopedToken requestToken(mySecureRestClient client, String resource_path, String username, long client_nonce, byte[] credentials)
			throws UnsupportedEncodingException, UnknownHostException, IOException, DeniedAccessException {

		RestResponse response = post_requestToken(client, resource_path, username, client_nonce, credentials);

		if (response.getStatusCode() == 200) {
			return (EnvelopedToken) response.getEntity(EnvelopedToken.class);
		} else if (response.getStatusCode() == 403) {
			String message = (String) response.getEntity(String.class);
			throw new DeniedAccessException(message);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}

	public static AuthenticationToken login(mySecureRestClient client, String resource_path, String username, String password, LoginUtility login)
			throws UnsupportedEncodingException, UnknownHostException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, ExpiredTokenException, WrongChallengeAnswerException,
			NoSuchPaddingException, DeniedAccessException, InvalidKeySpecException {

		// Request a session
		SessionEstablishmentParameters msg1 = requestSession(client, resource_path, username);

		// Generate Key Pair
		SecureRandom sr = SecureRandom.getInstance(msg1.getSecure_random_algorithm());

		DiffieHellman dh_local = new DiffieHellman(msg1.getP(), msg1.getG(), msg1.getSecret_key_size(),
				msg1.getSecret_key_algorithm(), msg1.getProvider(), sr);

		KeyPair myKeyPair = dh_local.genKeyPair();

		// Obtain key through password
		byte[] p_hash = Cryptography.digest(login.getHash(), password.getBytes());
		String encoded_password = java.util.Base64.getEncoder().encodeToString(p_hash);
		Cipher[] ciphers = login.getCipherPair(encoded_password, msg1.getNonce() + 1);

		byte[] credentials = buildCredentials(ciphers[0], username, msg1.getNonce() + 1, myKeyPair.getPublic());

		// Request Token
		long client_nonce = Cryptography.genNonce(sr);
		
		EnvelopedToken envToken = requestToken(client, resource_path, username, client_nonce, credentials);
		
		byte[] server_ans = Cryptography.decrypt(ciphers[1], envToken.getServer_answer());
		Entry<String, byte[]> e = retrieveServerPubKey(server_ans, client_nonce+1);
		PublicKey server_pub_key = Cryptography.parsePublicKey(e.getKey(), dh_local.getKeyFactory());
		SecretKey ks = dh_local.establishSecretKey(myKeyPair.getPrivate(), server_pub_key);
		byte[] iv = e.getValue();

		Cipher cipher = Cryptography.buildCipher(msg1.getEncryption_algorithm(), Cipher.DECRYPT_MODE, ks, iv, msg1.getProvider());

		AuthenticationToken token = AuthenticationToken.parseToken(envToken.getToken(), cipher);

		if (!token.isExpired(System.currentTimeMillis()))
			return token;
		else
			throw new ExpiredTokenException();
	}

	private static Entry<String, byte[]> retrieveServerPubKey(byte[] server_answer, long expectd_challenge_answer) throws WrongChallengeAnswerException, IOException {
		ByteArrayInputStream byteIn = new ByteArrayInputStream(server_answer);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		long challenge_answer = dataIn.readLong();
		String server_pubKey = dataIn.readUTF();
		int iv_len = dataIn.readInt();
		byte[] iv = new byte[iv_len];
		dataIn.read(iv, 0, iv_len);
		
		dataIn.close();
		byteIn.close();
		
		if (expectd_challenge_answer == challenge_answer) {
			return new AbstractMap.SimpleEntry<String, byte[]>(server_pubKey, iv);
		} else {
			throw new WrongChallengeAnswerException();
		}
	}

	private static byte[] buildCredentials(Cipher cipher, String username, long challenge_answer, PublicKey publicKey)
			throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, ShortBufferException {

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeUTF(username);
		dataOut.writeLong(challenge_answer); 
		dataOut.writeUTF(Cryptography.encodePublicKey(publicKey));

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return Cryptography.encrypt(cipher, msg);
	}
	
}
