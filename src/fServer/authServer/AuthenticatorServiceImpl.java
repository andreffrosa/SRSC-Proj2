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

import rest.client.RestResponse;
import utility.Cryptography;

public class AuthenticatorServiceImpl implements AuthenticatorService {

	private static final int GC_FACTOR = 3;
	private static final long REQUEST_TTL = 5*60*1000; // 5min

	private Map<String,SessionPendingRequest> pending_requests;
	private Map<String,User> authentication_table;
	private SecureRandom sr;
	private DiffieHellman dh;
	private TokenIssuer tokenIssuer;

	public AuthenticatorServiceImpl(DiffieHellman dh, Map<String,User> authentication_table, TokenIssuer tokenIssuer) {
		this.dh = dh;
		this.sr = dh.getSecureRandom();
		this.authentication_table = authentication_table;
		this.tokenIssuer = tokenIssuer;
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

	// Gerar dinâmicamente
	private static byte[] iv = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
	
	// TODO: O que fazer com as excepções? Lançar throw?

	@Override
	public RestResponse requestSession(String username) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		User user = authentication_table.get(username);
		if(user != null) {
			if(user.isAllowed()) {
				// Generate a nonce and a KeyPair for this request
				long nonce = Cryptography.genNonce(sr);
				DHParameterSpec dhParams = dh.getParams();
				KeyPair	kp = dh.genKeyPair();

				pending_requests.put(username, new SessionPendingRequest(nonce+1, kp, System.currentTimeMillis() + REQUEST_TTL));

				// TODO: Enviar um IV dinâmico como arg
				DH_MSG1 msg1 = new DH_MSG1(nonce, dhParams.getP(), dhParams.getG(), dh.getSecret_key_size(), 
						Cryptography.encodePublicKey(kp.getPublic()), 
						dh.getSecret_key_algorithm(), dh.getCiphersuite(), 
						dh.getSecureRandom().getAlgorithm(), dh.getProvider(), iv);

				return new RestResponse("1.0", 200, "OK", msg1);
			} else {
				return new RestResponse("1.0", 403, "Forbidden", (username + " is blocked!").getBytes());
			}
		} else {
			return new RestResponse("1.0", 403, "Forbidden", (username + " is not registered!").getBytes());
		}
	}

	@Override
	public RestResponse requestToken(String username, String user_public_value, long client_nonce, byte[] credentials) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {

		SessionPendingRequest request = this.pending_requests.get(username);

		if(request != null) {
			User user = authentication_table.get(username);

			PublicKey cliet_pub_key = Cryptography.parsePublicKey(user_public_value, dh.getKeyFactory());

			SecretKey ks = dh.establishSecretKey(request.getKey_pair().getPrivate(), cliet_pub_key);

			// TODO: Passar estas definições para um ficheiro e enviar para o cliente na 1ª msg para ele saber como cifrar as coisas
			
			Cipher cipher = Cryptography.buildCipher(dh.getCiphersuite(), Cipher.DECRYPT_MODE, ks, iv);

			Entry<byte[], Long> e = parseMessage3(credentials, cipher);

			String password = java.util.Base64.getEncoder().encodeToString(e.getKey());
			long nonce_answer = e.getValue();
			
			if(password.equals(user.getPassword())) {

				// Verify answer
				if(nonce_answer == request.getChallenge_answer()) {

					AuthenticationToken token = tokenIssuer.newToken(user);

					cipher.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));

					byte[] msg2 = wrapToken(token, client_nonce + 1, cipher);
					
					return new RestResponse("1.0", 200, "OK", msg2);
				} else {
					return new RestResponse("1.0", 403, "Forbidden", ("Nonce does not match!").getBytes());
				}
			} else {
				return new RestResponse("1.0", 403, "Forbidden", ("Wrong password!").getBytes());
			}
		} else {
			return new RestResponse("1.0", 403, "Forbidden", (username + " has no pedding request!").getBytes());
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
