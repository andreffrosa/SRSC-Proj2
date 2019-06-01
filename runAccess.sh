#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/mySecureREST-0.0.1-SNAPSHOT-jar-with-dependencies.jar"

JAVA_ARGS="-Djava.net.preferIPv4Stack=true"

PORT="6666"
TLS="./configs/fServer/servertls.conf"
KEYSTORE="./configs/fServer/accessControlServer/keystores.conf"
TABLE="./configs/fServer/accessControlServer/access_table.txt"
TOKEN="./configs/fServer/token_verification.conf"

$JAVA $JAVA_ARGS $CP fServer.accessControlServer.AccessControlServer $PORT $TLS $KEYSTORE $TABLE $TOKEN $@
