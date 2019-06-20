#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/mySecureREST-0.0.1-SNAPSHOT-jar-with-dependencies.jar"

JAVA_ARGS="-Djava.net.preferIPv4Stack=true"

SERVER="https://localhost:8888/"
KEYSTORES="./configs/client/keystores.conf"
LOGIN="./configs/client/login.conf"
ENCRYPTED_FS="./configs/client/encrypted-file-system.conf"

$JAVA $JAVA_ARGS $CP client.ConsoleClient $SERVER $KEYSTORES $LOGIN $ENCRYPTED_FS $@
