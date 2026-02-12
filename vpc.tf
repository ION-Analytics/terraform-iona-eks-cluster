data "aws_availability_zones" "available" {
}

resource "aws_security_group" "eks_cluster_allow_inbound" {
    name        = "${var.name}-eks-cluster-sg"
    description = "EKS Cluster security group"
    vpc_id      = var.platform_config.vpc
    ingress {
            description            = "Allow all inbound traffic to EKS cluster security group"
            from_port              = 0
            to_port                = 0
            protocol               = "all"
            cidr_blocks            = var.inbound_cidr_blocks
    }
    egress {
            description            = "Allow all outbound traffic"
            from_port              = 0
            to_port                = 0
            protocol               = "-1"
            cidr_blocks            = ["0.0.0.0/0"]
    }
}

# Allow control plane to communicate with nodes on kubelet port
resource "aws_security_group_rule" "node_ingress_from_cluster" {
    description              = "Allow cluster control plane to communicate with worker nodes (kubelet)"
    from_port                = 10250
    protocol                 = "tcp"
    security_group_id        = aws_security_group.eks_cluster_sg_allow_ssh.id
    source_security_group_id = aws_security_group.eks_cluster_allow_inbound.id
    to_port                  = 10250
    type                     = "ingress"
}

# Allow nodes to communicate with each other
resource "aws_security_group_rule" "node_ingress_self" {
    description       = "Allow worker nodes to communicate with each other"
    from_port         = 0
    protocol          = "-1"
    security_group_id = aws_security_group.eks_cluster_sg_allow_ssh.id
    self              = true
    to_port           = 65535
    type              = "ingress"
}

# Allow pods to communicate with the cluster API Server
resource "aws_security_group_rule" "cluster_ingress_from_node_pods" {
    description              = "Allow pods to communicate with the cluster API Server"
    from_port                = 443
    protocol                 = "tcp"
    security_group_id        = aws_security_group.eks_cluster_allow_inbound.id
    source_security_group_id = aws_security_group.eks_cluster_sg_allow_ssh.id
    to_port                  = 443
    type                     = "ingress"
}

resource "aws_security_group" "eks_cluster_sg_allow_ssh" {
    name        = "${var.name}-eks-node-groups-sg"
    description = "EKS Cluster security group"
    vpc_id      = aws_eks_cluster.cluster.vpc_config[0].vpc_id
    ingress {
            description            = "Allow all inbound traffic to EKS cluster security group"
            from_port              = 22
            to_port                = 22
            protocol               = "tcp"
            cidr_blocks            = var.inbound_cidr_blocks
    }
    egress {
            description            = "Allow all outbound traffic"
            from_port              = 0
            to_port                = 0
            protocol               = "-1"
            cidr_blocks            = ["0.0.0.0/0"]
    }
}