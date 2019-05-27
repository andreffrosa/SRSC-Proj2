package fServer.authServer;

import java.math.BigInteger;

public class SessionEstablishmentParameters {

	private long nonce;
	private BigInteger p;
	private BigInteger g;
	private int secret_key_size;
	private String public_value;
	private String secret_key_algorithm;
	private String encryption_algorithm;
	private String secure_random_algorithm;
	private String provider;

	public SessionEstablishmentParameters(long nonce, BigInteger p, BigInteger g, int secret_key_size, String public_value, String secret_key_algorithm, String encryption_algorithm, String secure_random_algorithm, String provider) {
		this.nonce = nonce;
		this.p = p;
		this.g = g;
		this.secret_key_size = secret_key_size;
		this.public_value = public_value;
		this.secret_key_algorithm = secret_key_algorithm;
		this.encryption_algorithm = encryption_algorithm;
		this.secure_random_algorithm = secure_random_algorithm;
		this.provider = provider;
	}

	public long getNonce() {
		return nonce;
	}

	public BigInteger getP() {
		return p;
	}

	public BigInteger getG() {
		return g;
	}

	public int getSecret_key_size() {
		return secret_key_size;
	}

	public String getPublic_value() {
		return public_value;
	}

	public String getSecret_key_algorithm() {
		return secret_key_algorithm;
	}

	public String getEncryption_algorithm() {
		return encryption_algorithm;
	}

	public String getSecure_random_algorithm() {
		return secure_random_algorithm;
	}

	public String getProvider() {
		return provider;
	}

}

