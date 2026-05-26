#!/bin/bash

kubectl apply -f redis_sygma.yaml
kubectl rollout status deploy/redis -w

kubectl apply -f core.yaml
kubectl rollout status ds/core -w

kubectl apply -f sygma-config-operator.yaml
kubectl rollout status deploy/sygma-config-operator -w

kubectl apply -f sygma-policy-agent.yaml
kubectl rollout status ds/sygma-policy-agent -w