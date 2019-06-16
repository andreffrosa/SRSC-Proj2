package fServer.authServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;

import rest.RestResponse;
import token.auth.AuthenticationToken;
import token.auth.AuthTokenIssuer;
import utility.Cryptography;
import utility.LoginUtility;

public class AuthenticatorServiceImpl implements AuthenticatorService {

	private static final int GC_FACTOR = 3;
	private static final long REQUEST_TTL = 5*60*1000; // 5min

	private Map<String,SessionPendingRequest> pending_requests;
	private Map<String,User> authentication_table;
	private SecureRandom sr;
	private DiffieHellman dh;
	private AuthTokenIssuer tokenIssuer;
	private LoginUtility login_util;

	public AuthenticatorServiceImpl(DiffieHellman dh, Map<String,User> authentication_table, AuthTokenIssuer tokenIssuer, LoginUtility login_util) {
		this.dh = dh;
		this.sr = dh.getSecureRandom();
		this.authentication_table = authentication_table;
		this.tokenIssuer = tokenIssuer;
		this.login_util = login_util;
		this.pending_requests = new HashMap<>();
		startGarbageCollector();
	}

	private void startGarbageCollector() {

		new Thread(()-> {
			while(true) {
				try {
					Thread.sleep(REQUEST_TTL*GC_FACTOR);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}

				long current_time = System.currentTimeMillis();
				GC_clean(current_time);
			}
		}).start();

	}
	
	private synchronized void GC_clean(long current_time) {
		pending_requests.entrySet().removeIf(entry -> entry.getValue().getExpiration_date() < current_time);
	}

	@Override
	public synchronized RestResponse requestSession(String username) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		User user = authentication_table.get(username);
		if(user != null) {
			if(user.isAllowed()) {
				// Generate a nonce for this request
				long nonce = Cryptography.genNonce(sr);
				DHParameterSpec dhParams = dh.getParams();

				pending_requests.put(username, new SessionPendingRequest(nonce+1, System.currentTimeMillis() + REQUEST_TTL));

				SessionEstablishmentParameters params = new SessionEstablishmentParameters(nonce, dhParams.getP(), dhParams.getG(), dh.getSecret_key_size(), 
						dh.getSecret_key_algorithm(), tokenIssuer.getCiphersuite(), 
						dh.getSecureRandom().getAlgorithm(), dh.getProvider());

				return new RestResponse("1.0", 200, "OK", params);
			} else {
				return new RestResponse("1.0", 403, "Forbidden", (username + " is blocked!"));
			}
		} else {
			return new RestResponse("1.0", 403, "Forbidden", (username + " is not registered!"));
		}
	}

	@Override
	public synchronized RestResponse requestToken(String username, long client_nonce, byte[] credentials) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {

		SessionPendingRequest request = this.pending_requests.get(username);

		if(request != null) {
			User user = authentication_table.get(username);

			// Obtain Key from password
			Cipher[] ciphers = login_util.getCipherPair(user.getPassword(), request.getChallenge_answer());

			PublicKey cliet_pub_key;
			try {
				String client_pubKey = retrieveClientPubKey(username, request.getChallenge_answer(), Cryptography.decrypt(ciphers[1], credentials));
				cliet_pub_key = Cryptography.parsePublicKey(client_pubKey, dh.getKeyFactory());
			} catch (InvalidUsernameException e1) {
				return new RestResponse("1.0", 403, "Forbidden", ("Wrong password!").getBytes());
			} catch (WrongChallengeAnswerException e1) {
				return new RestResponse("1.0", 403, "Forbidden", ("Nonce does not match!"));
			}
			
			// Generate Key Pair
			KeyPair	kp = dh.genKeyPair();
			SecretKey ks = dh.establishSecretKey(kp.getPrivate(), cliet_pub_key);

			// Generate new token
			Entry<AuthenticationToken, byte[]> e = tokenIssuer.newToken(user, ks);
			AuthenticationToken token = e.getKey();
			byte[] iv = e.getValue();
			
			EnvelopedToken encToken = encapsulateToken(token, ks, iv, ciphers[0], client_nonce+1,  kp.getPublic());
		
			System.out.println( username + " logged in! Token valid until " + new Date(token.getExpiration_date()).toString());
			
			return new RestResponse("1.0", 200, "OK", encToken);
		} else {
			return new RestResponse("1.0", 403, "Forbidden", (username + " has no pending request!"));
		}
	}

	private synchronized EnvelopedToken encapsulateToken(AuthenticationToken token, SecretKey ks, byte[] iv, Cipher encCipher, long challenge_answer, PublicKey myPubKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, IOException {

		byte[] server_answer = buildAnswer(challenge_answer, myPubKey, iv, encCipher);

		return new EnvelopedToken(token.serialize(), server_answer);
	}

	private synchronized byte[] buildAnswer(long challenge_answer, PublicKey pubKey, byte[] encrypted_iv, Cipher cipher) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(challenge_answer);
		dataOut.writeUTF(Cryptography.encodePublicKey(pubKey));
		dataOut.writeInt(encrypted_iv.length);
		dataOut.write(encrypted_iv, 0, encrypted_iv.length);

		dataOut.flush();
		byteOut.flush();

		byte[] payload = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return Cryptography.encrypt(cipher, payload);
	}

	private String retrieveClientPubKey(String username, long challenge_answer, byte[] decrypted_credentials) throws IOException, InvalidUsernameException, WrongChallengeAnswerException {
		ByteArrayInputStream byteIn = new ByteArrayInputStream(decrypted_credentials);
		DataInputStream dataIn = new DataInputStream(byteIn);

		String recv_username = dataIn.readUTF();
		long recv_challenge_answer = dataIn.readLong();
		String client_pub_key = dataIn.readUTF();

		dataIn.close();
		byteIn.close();

		if(recv_username.equals(username)) {
			if(recv_challenge_answer == challenge_answer) {
				return client_pub_key;
			} else {
				throw new WrongChallengeAnswerException();
			}
		} else {
			throw new InvalidUsernameException();
		}

	}
	
}
