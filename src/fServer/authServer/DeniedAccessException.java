package fServer.authServer;

public class DeniedAccessException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public DeniedAccessException() {
		super();
	}

	public DeniedAccessException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public DeniedAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	public DeniedAccessException(String message) {
		super(message);
	}

	public DeniedAccessException(Throwable cause) {
		super(cause);
	}
	
}
