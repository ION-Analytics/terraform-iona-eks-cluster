data "aws_eks_addon_version" "vpc_cni"{
    addon_name         = "vpc-cni"
    kubernetes_version = aws_eks_cluster.cluster.version
    most_recent        = true
}

resource "aws_eks_addon" "vpc_cni" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "vpc-cni"
    addon_version   = data.aws_eks_addon_version.vpc_cni.version
    depends_on      = [aws_eks_cluster.cluster]
}

data "aws_eks_addon_version" "kube_proxy"{
    addon_name = "kube-proxy"
    kubernetes_version = aws_eks_cluster.cluster.version
    most_recent        = true
}
resource "aws_eks_addon" "kube_proxy" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "kube-proxy"
    addon_version   = data.aws_eks_addon_version.kube_proxy.version
    depends_on      = [aws_eks_cluster.cluster]
}

data "aws_eks_addon_version" "core_dns"{
    addon_name         = "coredns"
    kubernetes_version = aws_eks_cluster.cluster.version
    most_recent        = true
}

resource "aws_eks_addon" "core_dns" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "coredns"
    addon_version   = data.aws_eks_addon_version.core_dns.version
    depends_on      = [aws_eks_node_group.node_group]
}

data "aws_eks_addon_version" "pod_identity"{
    addon_name         = "eks-pod-identity-agent"
    kubernetes_version = aws_eks_cluster.cluster.version
    most_recent        = true

}

resource "aws_eks_addon" "pod_identity" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "eks-pod-identity-agent"
    addon_version   = data.aws_eks_addon_version.pod_identity.version
    depends_on      = [aws_eks_cluster.cluster]
}