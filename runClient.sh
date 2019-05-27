#JAVA="/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
JAVA=$JAVA_HOME/jre/bin/java

CP="-cp target/classes/:target/dependency/*:../mySecureREST/target/classes/:../mySecureREST/target/classes/*"

SERVER="https://localhost:8888/"
KEYSTORES="./configs/client/keystores.conf"
LOGIN="./configs/client/login.conf"

$JAVA $CP client.ConsoleClient $SERVER $KEYSTORES $LOGIN $@
