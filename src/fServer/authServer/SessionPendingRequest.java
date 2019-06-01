package fServer.authServer;

public class SessionPendingRequest {

	private long challenge_answer;
	private long expiration_date;
	
	public SessionPendingRequest(long challenge_answer, long expiration_date) {
		this.challenge_answer = challenge_answer;
		this.expiration_date = expiration_date;
	}

	public long getChallenge_answer() {
		return challenge_answer;
	}

	public void setChallenge_answer(long challenge_answer) {
		this.challenge_answer = challenge_answer;
	}

	public long getExpiration_date() {
		return expiration_date;
	}

	public void setExpiration_date(long expiration_date) {
		this.expiration_date = expiration_date;
	}
	
}
