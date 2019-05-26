package fServer.authServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import rest.client.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import utility.Cryptography;

public class AuthenticationClient {

	private mySecureRestClient client;
	
	public AuthenticationClient(KeyStore ks, String ks_password, KeyStore ts, String location)
			throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnknownHostException, CertificateException, IOException {

		this.client = new mySecureRestClient(new CustomSSLSocketFactory(ks, ks_password, ts), location);
	}
	
	// TODO: Mudar o nome da class do resultado
	public DH_MSG1 requestSession(String username) throws UnsupportedEncodingException, UnknownHostException, IOException {
		RestResponse response = client.newRequest(AuthenticatorService.PATH)
									.addPathParam("requestSession")
									.addPathParam(username).get();

		// TODO: fazer lançamento de excepções quando vem um erro
		if (response.getStatusCode() == 200) {
			return (DH_MSG1) response.getEntity(DH_MSG1.class);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}
	
	public byte[] requestToken(String username, String user_public_value, long client_nonce, byte[] credentials) throws Exception {
		RestResponse response = client.newRequest(AuthenticatorService.PATH)
				.addPathParam("requestToken")
				.addPathParam(username)
				.addPathParam(user_public_value)
				.addQueryParam("client_nonce", "" + client_nonce)
				.post(credentials);

		// TODO: lançar excepções
		if (response.getStatusCode() == 200) {
			return (byte[]) response.getEntity(byte[].class);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}
	
	public AuthenticationToken login(String username, String password, MessageDigest hash) throws Exception {
		
		DH_MSG1 msg1 = requestSession(username);

		SecureRandom sr = SecureRandom.getInstance(msg1.getSecure_random_algorithm());
		
		// TODO: colocar uma seed diferente no sr?
		
		// Establish a shared key
		DiffieHellman dh_local = new DiffieHellman(msg1.getP(), msg1.getG(), msg1.getSecret_key_size(), 
							msg1.getSecret_key_algorithm(), msg1.getProvider(), 
							sr, msg1.getEncryption_algorithm(), msg1.getIv()!=null);

		KeyPair myKeyPair = dh_local.genKeyPair();
		PublicKey server_pub_key = Cryptography.parsePublicKey(msg1.getPublic_value(), dh_local.getKeyFactory());
		SecretKey ks = dh_local.establishSecretKey(myKeyPair.getPrivate(), server_pub_key);

		byte[] p_hash = Cryptography.digest(hash, password.getBytes());

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.writeInt(p_hash.length);
		dataOut.write(p_hash);
		dataOut.writeLong(msg1.getNonce()+1);

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		IvParameterSpec iv = new IvParameterSpec(msg1.getIv());
		
		Cipher cipher = Cipher.getInstance(msg1.getEncryption_algorithm());
		cipher.init(Cipher.ENCRYPT_MODE, ks, iv);
		byte[] credentials = Cryptography.encrypt(cipher, msg);

		dataOut.close();
		byteOut.close();

		String user_public_value = java.util.Base64.getEncoder().encodeToString(myKeyPair.getPublic().getEncoded());
		long client_nonce = Cryptography.genNonce(sr);

		byte[] msg2 = requestToken(username, user_public_value, client_nonce, credentials);

		cipher.init(Cipher.DECRYPT_MODE, ks, iv);
		byte[] raw = Cryptography.decrypt(cipher, msg2);

		ByteArrayInputStream byteIn = new ByteArrayInputStream(raw);
		DataInputStream dataIn = new DataInputStream(byteIn);

		int token_size = dataIn.readInt();
		byte[] raw_token = new byte[token_size];
		dataIn.read(raw_token, 0, token_size);

		long challenge_answer = dataIn.readLong();

		dataIn.close();
		byteIn.close();
		
		if(client_nonce+1 == challenge_answer) {
			AuthenticationToken token = AuthenticationToken.parseToken(raw_token);
			
			if(!token.isExpired(System.currentTimeMillis()))
				return token;
			else
				return null; // TODO: lançar Excepção
		} else {
			return null; // TODO: lançar excepção
		}
	}
}
