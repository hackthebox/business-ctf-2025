#!/bin/bash

########### ENV VARS ###########
NAME=blockout
IMAGE=blockchain_${NAME}
HANDLER_PORT=8000
LOCAL_RPC_PORT=5000
PUBLIC_RPC_PORT=8888
###############################

docker stop $IMAGE
docker rm -f $IMAGE
docker build --tag=$IMAGE:latest ./challenge/ && \
docker run --rm -it -d \
    -p "$PUBLIC_RPC_PORT:$LOCAL_RPC_PORT" \
    -p "$HANDLER_PORT:$HANDLER_PORT" \
    --name $IMAGE \
    $IMAGE:latest
