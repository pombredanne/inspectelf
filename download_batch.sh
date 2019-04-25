#!/bin/bash

while read p; do
	./inspectelf/versions_download.py $p
done < $1
