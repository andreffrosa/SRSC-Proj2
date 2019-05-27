#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/mySecureREST-0.0.1-SNAPSHOT-jar-with-dependencies.jar"

PORT="6666"
TLS="./configs/fServer/servertls.conf"
KEYSTORE="./configs/fServer/accessControlServer/keystores.conf"
ENDPOINTS="./configs/fServer/service-endpoints.txt"
TOKEN="./configs/fServer/token_verification.conf"

$JAVA $CP fServer.mainDispatcher.MainDispatcherServer $PORT $TLS $KEYSTORE $ENDPOINTS $TOKEN $@
