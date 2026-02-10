#!/bin/bash
set -ex

# Create nodeadm configuration with registry mirror
cat <<EOF > /etc/eks/nodeadm-config.yaml
---
apiVersion: node.eks.aws/v1alpha1
kind: NodeConfig
spec:
  cluster:
    name: ${cluster_name}
    apiServerEndpoint: ${cluster_endpoint}
    certificateAuthority: ${cluster_ca_data}
  containerd:
    config: |
      version = 2
      [plugins."io.containerd.grpc.v1.cri".registry]
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
          [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
            endpoint = ["https://${registry_mirror_url}", "https://registry-1.docker.io"]
EOF

# Initialize the node using nodeadm
/usr/bin/nodeadm init -c file:///etc/eks/nodeadm-config.yaml
