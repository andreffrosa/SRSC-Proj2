#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/classes/:../mySecureREST/target/classes/*"

PORT="9999"
TLS="./configs/fServer/servertls.conf"
KEYSTORE="./configs/fServer/mainDispatcher/keystores.conf"
ENDPOINTS="./configs/fServer/service-endpoints.txt"
TOKEN="./configs/fServer/token_verification.conf"

$JAVA $CP fServer.storageServer.StorageServer $PORT $TLS $KEYSTORE $ENDPOINTS $TOKEN $@
