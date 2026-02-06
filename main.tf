resource "aws_eks_cluster" "cluster" {
    name    = var.name
    role_arn = aws_iam_role.eks_cluster_role.arn

    vpc_config {
        subnet_ids = split(",", var.platform_config.private_subnets)
        
        endpoint_private_access = true
        endpoint_public_access  = false
        security_group_ids = [aws_security_group.eks_cluster_allow_inbound.id]
    }

    kubernetes_network_config {
        service_ipv4_cidr = var.internal_vpc_cidr 
    }

    version = var.kubernetes_version

    upgrade_policy {
        support_type = "STANDARD"
    }

    access_config {
        authentication_mode = "API_AND_CONFIG_MAP"
    }

}

data "aws_ssm_parameter" "eks_ami_release_version" {
  name = "/aws/service/eks/optimized-ami/${aws_eks_cluster.cluster.version}/amazon-linux-2023/x86_64/standard/recommended/release_version"
}

resource "aws_eks_node_group" "node_group" {
    cluster_name    = aws_eks_cluster.cluster.name
    node_group_name = "${var.name}-eks-node-group-asg"
    node_role_arn   = aws_iam_role.eks_node_role.arn
    subnet_ids      = aws_eks_cluster.cluster.vpc_config[0].subnet_ids

    scaling_config {
        desired_size = 2
        max_size     = 3
        min_size     = 1
    }

    instance_types = var.woker_node_instance_types

    version = aws_eks_cluster.cluster.version
    release_version = nonsensitive(data.aws_ssm_parameter.eks_ami_release_version.value)
    
    disk_size      = 20
    
    dynamic remote_access {
        for_each = var.ssh_keys
        content {
            ec2_ssh_key = remote_access.value
            source_security_group_ids = [aws_security_group.eks_cluster_sg_allow_ssh.id]
        }
    }

    tags = {
        Name = "${var.name}-eks-node-group-asg"
    }
}

data "aws_eks_addon_versions" "vpc_cni"{
    addon_name = "vpc-cni"
    kubernetes_version = aws_eks_cluster.cluster.version
}

resource "aws_eks_addon" "vpc_cni" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "vpc-cni"
    addon_version   = data.aws_eks_addon_versions.vpc_cni.addons[0].addon_versions[0].latest_version
    depends_on      = [aws_eks_cluster.cluster]
}

data "aws_eks_addon_versions" "kube_proxy"{
    addon_name = "kube-proxy"
    kubernetes_version = aws_eks_cluster.cluster.version
}
resource "aws_eks_addon" "kube_proxy" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "kube-proxy"
    addon_version   = data.aws_eks_addon_versions.kube_proxy.addons[0].addon_versions[0].latest_version
    depends_on      = [aws_eks_cluster.cluster]
}

data "aws_eks_addon_versions" "core_dns"{
    addon_name = "coredns"
    kubernetes_version = aws_eks_cluster.cluster.version
}

resource "aws_eks_addon" "core_dns" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "coredns"
    addon_version   = data.aws_eks_addon_versions.core_dns.addons[0].addon_versions[0].latest_version
    depends_on      = [aws_eks_cluster.cluster]
}

data "aws_eks_addon_versions" "pod_identity"{
    addon_name = "eks-pod-identity-agent"
    kubernetes_version = aws_eks_cluster.cluster.version
}

resource "aws_eks_addon" "pod_identity" {
    cluster_name    = aws_eks_cluster.cluster.name
    addon_name      = "eks-pod-identity-agent"
    addon_version   = data.aws_eks_addon_versions.pod_identity.addons[0].addon_versions[0].latest_version
    depends_on      = [aws_eks_cluster.cluster]
}

resource "aws_eks_access_policy_association" "admin_access" {
  cluster_name  = aws_eks_cluster.cluster.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = var.iam_role_eks_admin_access

  access_scope {
    type       = "cluster"
  }
}