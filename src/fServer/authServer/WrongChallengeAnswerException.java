package fServer.authServer;

public class WrongChallengeAnswerException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public WrongChallengeAnswerException() {
		super();
	}

	public WrongChallengeAnswerException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public WrongChallengeAnswerException(String message, Throwable cause) {
		super(message, cause);
	}

	public WrongChallengeAnswerException(String message) {
		super(message);
	}

	public WrongChallengeAnswerException(Throwable cause) {
		super(cause);
	}

	
}
