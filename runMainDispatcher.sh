#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/mySecureREST-0.0.1-SNAPSHOT-jar-with-dependencies.jar"

JAVA_ARGS="-Djava.net.preferIPv4Stack=true"

PORT="8888"
TLS="./configs/fServer/servertls.conf"
KEYSTORE="./configs/fServer/mainDispatcher/keystores.conf"
ENDPOINTS="./configs/fServer/service-endpoints.txt"
AUTH_TOKEN="./configs/fServer/auth_token_verification.conf"
ACCESS_TOKEN="./configs/fServer/access_token_verification.conf"

$JAVA $JAVA_ARGS $CP fServer.mainDispatcher.MainDispatcherServer $PORT $TLS $KEYSTORE $ENDPOINTS $AUTH_TOKEN $ACCESS_TOKEN $@
