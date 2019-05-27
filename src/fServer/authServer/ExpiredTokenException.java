package fServer.authServer;

public class ExpiredTokenException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public ExpiredTokenException() {
		super();
	}

	public ExpiredTokenException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public ExpiredTokenException(String message, Throwable cause) {
		super(message, cause);
	}

	public ExpiredTokenException(String message) {
		super(message);
	}

	public ExpiredTokenException(Throwable cause) {
		super(cause);
	}

}
