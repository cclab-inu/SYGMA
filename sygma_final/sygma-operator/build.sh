#!/bin/bash

IMAGE_NAME="sygma-operator"
TAG="latest"

echo "1. Docker   ..."
docker build -t ${IMAGE_NAME}:${TAG} .
docker tag ${IMAGE_NAME}:${TAG} acsac2026/${IMAGE_NAME}:${TAG}
docker push acsac2026/${IMAGE_NAME}:${TAG}
echo "✅   "