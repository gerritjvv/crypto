#!/usr/bin/env bash

DIR=$(cd -P -- "$(dirname -- "$0")" && pwd -P)


build () {


(cd "$DIR/../crypto-core" \
&& mvn clean install
 )

(cd "$DIR" \
&& mvn clean install
 )

}

run () {
echo "RUN"


CP=$(find "$DIR"/target/lib -iname "*.jar" | paste -s -d:  -)

java -Xmx1g -Xms1g -cp "$CP:$DIR/target/benchmarks.jar" org.openjdk.jmh.Main


}

CMD="$1"
shift

case "$CMD" in

    build)
    build
    ;;

    run)
    run
    ;;

    * )
    echo "./build.sh build|run"
    ;;
esac