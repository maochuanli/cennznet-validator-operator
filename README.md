# cennznet-validator-operator

kubectl create clusterrolebinding cluster-admin-binding-4-operator \
    --clusterrole cluster-admin \
    --user "system:serviceaccount:az-ie-cennznet-validator-operator:cennznet-validator-operator-service-account"

