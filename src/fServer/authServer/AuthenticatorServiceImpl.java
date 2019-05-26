package fServer.authServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
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
import javax.crypto.spec.IvParameterSpec;

import utility.Cryptography;
import utility.DiffieHellman;

public class AuthenticatorServiceImpl implements AuthenticatorService {

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
	}

	// TODO: precisa de um GC para apagar os pending requests que estão expirados
	// TODO: O que fazer com as excepções? Lançar throw?

	@Override
	public DH_MSG1 requestSession(String username) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

		// TODO: Verificar coisas sobre o username antes de fazer o resto

		User user = authentication_table.get(username);
		if( user != null) {
			if(user.isAllowed()) {
				// Generate a nonce and a KeyPair
				long nonce = Cryptography.genNonce(sr);
				DHParameterSpec dhParams = dh.getParams();
				KeyPair	kp = dh.genKeyPair();

				pending_requests.put(username, new SessionPendingRequest(nonce+1, kp, System.currentTimeMillis()+REQUEST_TTL));

				// TODO: passar o algoritmo de cifra como arg
				return new DH_MSG1(nonce, dhParams.getP(), dhParams.getG(), dh.getSecret_key_size(), Cryptography.encodePublicKey(kp.getPublic()), dh.getSecret_key_algorithm(), "AES/CBC/PKCS5Padding", dh.getSecureRandom().getAlgorithm(), dh.getProvider());
			} else {
				; // TODO: O que enviar como resposta?
			}
		} else {
			; // TODO: O que enviar como resposta?
		}
		return null;
		}

	@Override
	public byte[] requestToken(String username, String user_public_value, long client_nonce, byte[] credentials) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {

		SessionPendingRequest request = this.pending_requests.get(username);
		User user = authentication_table.get(username);

		if(request != null) {
			
			PublicKey cliet_pub_key = Cryptography.parsePublicKey(user_public_value, dh.getKeyFactory());

			SecretKey ks = dh.establishSecretKey(request.getKey_pair().getPrivate(), cliet_pub_key);

			// TODO: Passar estas definições para um ficheiro e enviar para o cliente na 1ª msg para ele saber como cifrar as coisas
			Cipher cipher = Cryptography.buildCipher("AES/CBC/PKCS5Padding", Cipher.DECRYPT_MODE, ks, new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15});

			byte[] decrypted_credentials = Cryptography.decrypt(cipher, credentials);

			ByteArrayInputStream byteIn = new ByteArrayInputStream(decrypted_credentials);
			DataInputStream dataIn = new DataInputStream(byteIn);

			MessageDigest hash = MessageDigest.getInstance("SHA512", "BC"); // TODO: guardar o digest length apenas
			byte[] p_hash = new byte[hash.getDigestLength()];
			dataIn.read(p_hash, 0, p_hash.length);
			
			long nonce_answer = dataIn.readLong();

			dataIn.close();
			byteIn.close();
			
			String password = java.util.Base64.getEncoder().encodeToString(p_hash);
			
			if(password.equals(user.getPassword())) {
				
				// Verify answer
				if(nonce_answer == request.getChallenge_answer()) {
					
					AuthenticationToken token = tokenIssuer.newToken(user);
					
					// TEMP
					Entry<PublicKey, Signature> e;
					try {
						e = TokenIssuer.getVerifier("./configs/fServer/token_verification.conf");
						
						System.out.println(java.util.Base64.getEncoder().encodeToString(token.getSignature()));
						
						System.out.println(token.isValid(System.currentTimeMillis(), e.getValue(), e.getKey()));
						System.out.println(token.isAuthentic(e.getValue(), e.getKey()));
						System.out.println(token.isExpired(System.currentTimeMillis()));
					} catch (KeyStoreException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (CertificateException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					
					
					cipher.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}));

					return wrapToken(token, client_nonce + 1, cipher);
				}
			} else {
				; // TODO: Enviar msg de erro
			}
		}

		return null; // TODO: lançar um erro?
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
	
}
