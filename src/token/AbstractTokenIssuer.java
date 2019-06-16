package token;

import java.security.KeyPair;
import java.security.Signature;

public abstract class AbstractTokenIssuer implements TokenIssuer {

	protected long token_ttl;
	protected KeyPair kp;
	protected Signature sig;

	public AbstractTokenIssuer(long token_ttl, KeyPair kp, Signature sig) {
		this.token_ttl = token_ttl;
		this.kp = kp;
		this.sig = sig;
	}

	public long getToken_ttl() {
		return token_ttl;
	}

	public KeyPair getKp() {
		return kp;
	}

	public Signature getSig() {
		return sig;
	}	

}
