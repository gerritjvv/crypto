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

 (cd "$DIR" && go test -v -cpu 1 -benchmem -cpuprofile "$DIR/"cpu.prof -memprofile "$DIR/"mem.prof -bench=. ./...)
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