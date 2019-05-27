#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/mySecureREST-0.0.1-SNAPSHOT-jar-with-dependencies.jar"

PORT="8050"
TLS="./configs/fServer/servertls.conf"
KEYSTORE="./configs/fServer/authenticationServer/keystores.conf"
AUTH_TABLE="./configs/fServer/authenticationServer/authentication_table.txt"
DH="./configs/fServer/authenticationServer/dh.conf"
TOKEN="./configs/fServer/authenticationServer/tokens.conf"

$JAVA $CP fServer.authServer.AuthenticationServer $PORT $TLS $KEYSTORE $AUTH_TABLE $DH $TOKEN $@
