#!/usr/bin/env bash


DIR=$(cd -P -- "$(dirname -- "$0")" && pwd -P)

CMD="$1"
shift

build () {


 (cd "$DIR" && go build ./...)

}

test () {

 (cd "$DIR" && go test -v ./...)

}

bench () {

 (cd "$DIR" && go test -v -bench=. ./...)
}

case "$CMD" in

 build )
   build
   ;;
 test )
   test
   ;;
 bench )
   bench
   ;;
 * )
   echo "build.sh build|test"

esac