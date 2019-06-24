#!/usr/bin/env bash

############################
#
#
############################



CMD="$1"
shift


case "$CMD" in

  release )
    mvn -Prelease deploy
    ;;
  install )
   mvn clean install
   ;;
  test )
   mvn test
   ;;
  * )
   echo "./build.sh test|install|release"
   ;;
esac
