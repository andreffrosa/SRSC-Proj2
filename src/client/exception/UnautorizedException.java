package client.exception;

public class UnautorizedException extends Exception {

	private static final long serialVersionUID = 1L;

	public UnautorizedException() { }

	public UnautorizedException(String message) { super(message);  }
}
