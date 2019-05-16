package utility;

public interface RequestHandler<T> {
	T execute(String arg);
}