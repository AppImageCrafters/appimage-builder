#!/bin/bash

declare -a MISSING_LIBS

echo "Starting libraries lockup"
for lib in "$@"; do
  /sbin/ldconfig -p | cut -f 2 -d'>' | grep $lib
  if [ $? -ne 0 ]; then
    MISSING_LIBS+=("$lib")
  fi
done

if [ ${#MISSING_LIBS[@]} -ne 0 ]; then
  echo "Missing libraries: "
  for lib in ${MISSING_LIBS[*]}; do
    echo " - $lib"
  done

  exit 1
fi

echo "Libraries lockup completed"
