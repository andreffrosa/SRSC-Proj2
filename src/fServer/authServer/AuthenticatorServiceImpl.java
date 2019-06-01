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
import java.util.AbstractMap;
import java.util.Date;
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
import javax.crypto.spec.IvParameterSpec;

import rest.RestResponse;
import utility.Cryptography;
import utility.LoginUtility;

public class AuthenticatorServiceImpl implements AuthenticatorService {

	private static final int GC_FACTOR = 3;
	private static final long REQUEST_TTL = 5*60*1000; // 5min

	private Map<String,SessionPendingRequest> pending_requests;
	private Map<String,User> authentication_table;
	private SecureRandom sr;
	private DiffieHellman dh;
	private TokenIssuer tokenIssuer;
	private LoginUtility login_util;

	public AuthenticatorServiceImpl(DiffieHellman dh, Map<String,User> authentication_table, TokenIssuer tokenIssuer, LoginUtility login_util) {
		this.dh = dh;
		this.sr = dh.getSecureRandom();
		this.authentication_table = authentication_table;
		this.tokenIssuer = tokenIssuer;
		this.login_util = login_util;
		this.pending_requests = new ConcurrentHashMap<>();
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
				pending_requests.entrySet().removeIf(entry -> entry.getValue().getExpiration_date() < current_time);
			}
		}).start();

	}

	@Override
	public RestResponse requestSession(String username) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		User user = authentication_table.get(username);
		if(user != null) {
			if(user.isAllowed()) {
				// Generate a nonce for this request
				long nonce = Cryptography.genNonce(sr);
				DHParameterSpec dhParams = dh.getParams();
				
				pending_requests.put(username, new SessionPendingRequest(nonce+1, System.currentTimeMillis() + REQUEST_TTL));

				SessionEstablishmentParameters msg1 = new SessionEstablishmentParameters(nonce, dhParams.getP(), dhParams.getG(), dh.getSecret_key_size(), 
						dh.getSecret_key_algorithm(), tokenIssuer.getCiphersuite(), 
						dh.getSecureRandom().getAlgorithm(), dh.getProvider());

				return new RestResponse("1.0", 200, "OK", msg1);
			} else {
				return new RestResponse("1.0", 403, "Forbidden", (username + " is blocked!").getBytes());
			}
		} else {
			return new RestResponse("1.0", 403, "Forbidden", (username + " is not registered!").getBytes());
		}
	}

	@Override
	public RestResponse requestToken(String username, long client_nonce, byte[] credentials) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {

		SessionPendingRequest request = this.pending_requests.get(username);

		if(request != null) {
			User user = authentication_table.get(username);
			
			Cipher[] ciphers = login_util.getCipherPair(user.getPassword(), request.getChallenge_answer());
			
			String client_pubKey = null;
			try {
				client_pubKey = retrieveClientPubKey(username, request.getChallenge_answer(), Cryptography.decrypt(ciphers[1], credentials));
			} catch (InvalidUsernameException e1) {
				//return new RestResponse("1.0", 403, "Forbidden", ("Username does not match!").getBytes());
				return new RestResponse("1.0", 403, "Forbidden", ("Wrong password!").getBytes());
			} catch (WrongChallengeAnswerException e1) {
				return new RestResponse("1.0", 403, "Forbidden", ("Nonce does not match!").getBytes());
			}
			
			PublicKey cliet_pub_key = Cryptography.parsePublicKey(client_pubKey, dh.getKeyFactory());
			
			KeyPair	kp = dh.genKeyPair();

			SecretKey ks = dh.establishSecretKey(kp.getPrivate(), cliet_pub_key);
			
			AuthenticationToken token = tokenIssuer.newToken(user);
			// TODO: gerar IV automaticamente
			Cipher cipher = Cryptography.buildCipher(tokenIssuer.getCiphersuite(), Cipher.DECRYPT_MODE, ks, tokenIssuer.getIv());
			cipher.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(tokenIssuer.getIv()));
			byte[] enc_token = Cryptography.encrypt(cipher, token.serialize());
			
			byte[] server_answer = buildAnswer(client_nonce+1, kp.getPublic(), Cryptography.encrypt(ciphers[0], tokenIssuer.getIv()), ciphers[0]);
			
			EncryptedToken encToken = new EncryptedToken(enc_token, server_answer);
			
			return new RestResponse("1.0", 200, "OK", encToken);
			
			/*	
			Entry<byte[], Long> e = parseMessage3(credentials, cipher);

			String password = java.util.Base64.getEncoder().encodeToString(e.getKey());
			long nonce_answer = e.getValue();
			
			if(password.equals(user.getPassword())) {

				// Verify answer
				if(nonce_answer == request.getChallenge_answer()) {

					AuthenticationToken token = tokenIssuer.newToken(user);

					cipher.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(tokenIssuer.getIv()));

					byte[] msg2 = wrapToken(token, client_nonce + 1, cipher);
					
					System.out.println(username + " authentication sucessful! Token valid until " + (new Date(token.getExpiration_date())).toString());
					
					return new RestResponse("1.0", 200, "OK", msg2);
				} else {
					return new RestResponse("1.0", 403, "Forbidden", ("Nonce does not match!").getBytes());
				}
			} else {
				return new RestResponse("1.0", 403, "Forbidden", ("Wrong password!").getBytes());
			}*/
		} else {
			return new RestResponse("1.0", 403, "Forbidden", (username + " has no pedding request!").getBytes());
		}
	}

	private byte[] buildAnswer(long challenge_answer, PublicKey pubKey, byte[] encrypted_iv, Cipher cipher) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeLong(challenge_answer);
		dataOut.writeUTF( Cryptography.encodePublicKey(pubKey));
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

	private byte[] wrapToken(AuthenticationToken token, long challenge_answer, Cipher cipher) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		byte[] raw_token = token.serialize();
		dataOut.writeInt(raw_token.length);
		dataOut.write(raw_token);
		dataOut.writeLong(challenge_answer);

		dataOut.flush();
		byteOut.flush();

		byte[] payload = byteOut.toByteArray();

		dataOut.close();
		byteOut.close();

		return Cryptography.encrypt(cipher, payload);
	}

	private Entry<byte[], Long> parseMessage3(byte[] credentials, Cipher cipher) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
	
		byte[] decrypted_credentials = Cryptography.decrypt(cipher, credentials);

		ByteArrayInputStream byteIn = new ByteArrayInputStream(decrypted_credentials);
		DataInputStream dataIn = new DataInputStream(byteIn);

		int hash_size = dataIn.readInt();
		
		byte[] p_hash = new byte[hash_size];
		dataIn.read(p_hash, 0, p_hash.length);

		long nonce_answer = dataIn.readLong();

		dataIn.close();
		byteIn.close();
		
		return new AbstractMap.SimpleEntry<byte[], Long>(p_hash, nonce_answer);
	}

}
