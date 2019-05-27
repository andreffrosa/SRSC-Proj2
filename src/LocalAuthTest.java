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
import javax.net.SocketFactory;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;

import fServer.authServer.AuthenticationClient;
import fServer.authServer.AuthenticationToken;
import fServer.authServer.AuthenticatorService;
import fServer.authServer.AuthenticatorServiceImpl;
import fServer.authServer.SessionEstablishmentParameters;
import fServer.authServer.DiffieHellman;
import fServer.authServer.TokenIssuer;
import fServer.authServer.TokenVerifier;
import fileService.RemoteFileService;
import rest.client.RestResponse;
import rest.client.mySecureRestClient;
import ssl.CustomSSLSocketFactory;
import utility.ArrayUtil;
import utility.Cryptography;
import utility.IO;
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
		//mySecureRestClient auth = new mySecureRestClient(new CustomSSLSocketFactory(kstore, ks_password, ts), location);

		// Simulation in B side

		System.out.println("Starting....");

		String username = "bina";
		String password = "larina";

		
		SocketFactory factory = new CustomSSLSocketFactory(kstore, ks_password, ts);
		mySecureRestClient client = new mySecureRestClient(factory, location);
		
		byte[] iv = ArrayUtil.unparse(IO.loadProperties("./configs/client/iv.conf").getProperty("IV"));
		
		AuthenticationToken token = AuthenticationClient.login(client, AuthenticatorService.PATH, username, password, hash, iv);
		
		System.out.println(token);
		System.out.println(java.util.Base64.getEncoder().encodeToString(token.getSignature()));
		TokenVerifier verifier = TokenVerifier.getVerifier("./configs/fServer/token_verification.conf");
		System.out.println(verifier.validateToken(System.currentTimeMillis(), token));
		/*System.out.println(token.isValid(System.currentTimeMillis(), e.getValue(), e.getKey()));
		System.out.println(token.isAuthentic(e.getValue(), e.getKey()));
		System.out.println(token.isExpired(System.currentTimeMillis()));
		Thread.sleep(10000);
		System.out.println(token.isValid(System.currentTimeMillis(), e.getValue(), e.getKey()));
		System.out.println(token.isAuthentic(e.getValue(), e.getKey()));
		System.out.println(token.isExpired(System.currentTimeMillis()));*/
	}

}
