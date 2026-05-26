#!/bin/bash

kubectl delete -f core.yaml
kubectl delete -f sygma-config-operator.yaml
kubectl delete -f sygma-policy-agent.yaml
kubectl delete -f redis_sygma.yaml