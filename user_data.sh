#!/bin/bash
set -ex

# Configure containerd registry mirror for docker.io
mkdir -p /etc/containerd/certs.d/docker.io
cat <<EOF > /etc/containerd/certs.d/docker.io/hosts.toml
server = "https://registry-1.docker.io"

[host."https://${registry_mirror_url}"]
  capabilities = ["pull", "resolve"]
  skip_verify = false
EOF

# Restart containerd to apply configuration
systemctl restart containerd

# Bootstrap the EKS node
/etc/eks/bootstrap.sh ${cluster_name}
