import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;

import fServer.authServer.AuthenticationToken;
import fServer.authServer.AuthenticatorService;
import fServer.authServer.AuthenticatorServiceImpl;
import fServer.authServer.DH_MSG1;
import fServer.authServer.TokenIssuer;
import fileService.RemoteFileService;
import rest.client.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import utility.Cryptography;
import utility.DiffieHellman;
import utility.MyKeyStore;
import utility.TLS_Utils;

public class LocalAuthTest {

	public static void main(String[] args) throws Exception {

		//SecureRandom sr = SecureRandom.getInstance("sha1PRNG");

		//      generate the key bytes
		MessageDigest	hash = MessageDigest.getInstance("SHA512", "BC");



		//////////////////////////////////////////////////////////////////
		String location = "https://localhost:8050/";
		// Load KeyStores
		MyKeyStore[] ks_stores = TLS_Utils.loadKeyStores("./configs/fServer/mainDispatcher/keystores.conf");
		KeyStore kstore = ks_stores[0].getKeystore();
		String ks_password = ks_stores[0].getPassword();
		KeyStore ts = ks_stores[1].getKeystore();
		mySecureRestClient auth = new mySecureRestClient(new CustomSSLSocketFactory(kstore, ks_password, ts), location);

		// Simulation in B side

		System.out.println("Starting....");

		String username = "bina";
		String password = "larina";
		
		DH_MSG1 msg1 = requestSession(auth, username);

		SecureRandom sr = SecureRandom.getInstance(msg1.getSecure_random_algorithm());
		
		// TODO: colocar uma seed diferente?
		
		DiffieHellman dh_local = new DiffieHellman(msg1.getP(), msg1.getG(), msg1.getSecret_key_size(), msg1.getSecret_key_algorithm(), msg1.getProvider(), sr);

		KeyPair bPair = dh_local.genKeyPair();

		PublicKey server_pub_key = Cryptography.parsePublicKey(msg1.getPublic_value(), dh_local.getKeyFactory());

		SecretKey ks = dh_local.establishSecretKey(bPair.getPrivate(), server_pub_key);

		byte[] p_hash = Cryptography.digest(hash, password.getBytes());

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);

		dataOut.write(p_hash);
		dataOut.writeLong(msg1.getNonce()+1);

		dataOut.flush();
		byteOut.flush();

		byte[] msg = byteOut.toByteArray();

		IvParameterSpec iv = new IvParameterSpec(new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15});
		
		Cipher cipher = Cipher.getInstance(msg1.getEncryption_algorithm());
		cipher.init(Cipher.ENCRYPT_MODE, ks, iv);
		byte[] credentials = Cryptography.encrypt(cipher, msg);

		dataOut.close();
		byteOut.close();

		String user_public_value = java.util.Base64.getEncoder().encodeToString(bPair.getPublic().getEncoded());
		long client_nonce = Cryptography.genNonce(sr);

		byte[] msg2 = requestToken(auth, username, user_public_value, client_nonce, credentials);

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
			System.out.println(token);
			System.out.println(java.util.Base64.getEncoder().encodeToString(token.getSignature()));
			Entry<PublicKey, Signature> e = TokenIssuer.getVerifier("./configs/fServer/token_verification.conf");
			System.out.println(token.isValid(System.currentTimeMillis(), e.getValue(), e.getKey()));
			System.out.println(token.isAuthentic(e.getValue(), e.getKey()));
			System.out.println(token.isExpired(System.currentTimeMillis()));
			Thread.sleep(10000);
			System.out.println(token.isValid(System.currentTimeMillis(), e.getValue(), e.getKey()));
			System.out.println(token.isAuthentic(e.getValue(), e.getKey()));
			System.out.println(token.isExpired(System.currentTimeMillis()));
		} else {
			; // TODO: O que fazer?
		}
	}

	// TODO: colocar numa class client
	private static DH_MSG1 requestSession(mySecureRestClient client, String username) throws Exception {
		RestResponse response = client.newRequest(AuthenticatorService.PATH).addPathParam("requestSession").addPathParam(username).get();

		if (response.getStatusCode() == 200) {
			return (DH_MSG1) response.getEntity(DH_MSG1.class);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}
	
	private static byte[] requestToken(mySecureRestClient client, String username, String user_public_value, long client_nonce, byte[] credentials) throws Exception {
		RestResponse response = client.newRequest(AuthenticatorService.PATH)
				.addPathParam("requestToken")
				.addPathParam(username)
				.addPathParam(user_public_value)
				.addQueryParam("client_nonce", "" + client_nonce)
				.post(credentials);

		if (response.getStatusCode() == 200) {
			return (byte[]) response.getEntity(byte[].class);
		} else
			throw new RuntimeException("requestSession: " + response.getStatusCode());
	}

}
