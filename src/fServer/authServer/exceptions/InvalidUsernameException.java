package fServer.authServer.exceptions;

public class InvalidUsernameException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InvalidUsernameException() {
		super();
	}

	public InvalidUsernameException(String arg0, Throwable arg1, boolean arg2, boolean arg3) {
		super(arg0, arg1, arg2, arg3);
	}

	public InvalidUsernameException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

	public InvalidUsernameException(String arg0) {
		super(arg0);
	}

	public InvalidUsernameException(Throwable arg0) {
		super(arg0);
	}

}
