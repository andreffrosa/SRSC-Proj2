package token;

import java.security.KeyPair;
import java.security.Signature;

public interface TokenIssuer {

	public long getToken_ttl();

	public KeyPair getKp();

	public Signature getSig();

}
