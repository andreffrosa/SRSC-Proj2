package fServer.authServer;

import java.security.KeyPair;

public class SessionPendingRequest {

	private long challenge_answer;
	private KeyPair key_pair;
	private long expiration_date;
	
	public SessionPendingRequest(long challenge_answer, KeyPair key_pair, long expiration_date) {
		this.challenge_answer = challenge_answer;
		this.key_pair = key_pair;
		this.expiration_date = expiration_date;
	}

	public long getChallenge_answer() {
		return challenge_answer;
	}

	public void setChallenge_answer(long challenge_answer) {
		this.challenge_answer = challenge_answer;
	}

	public KeyPair getKey_pair() {
		return key_pair;
	}

	public void setKey_pair(KeyPair key_pair) {
		this.key_pair = key_pair;
	}

	public long getExpiration_date() {
		return expiration_date;
	}

	public void setExpiration_date(long expiration_date) {
		this.expiration_date = expiration_date;
	}
	
}
