#!/bin/bash
NAME=gridcryp
IMAGE=ics_${NAME}
TCP_PORT=4840

docker rm -f $IMAGE
docker build --tag=$IMAGE . && \
docker run --rm -it \
    -p "$TCP_PORT:$TCP_PORT" \
    --name $IMAGE \
    $IMAGE