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
}