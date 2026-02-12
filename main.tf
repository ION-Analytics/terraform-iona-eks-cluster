data "aws_caller_identity" "current" {}

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

data "aws_ami_ids" "eks_ami" {
    owners = ["amazon"]
    filter {
        name   = "name"
        values = ["amazon-eks-node-al2023-x86_64-standard-${var.kubernetes_version}-*"]
    }
}

resource "aws_launch_template" "eks_node_group" {
    name_prefix   = "${var.name}-eks-node-template-"

    image_id      = data.aws_ami_ids.eks_ami.ids[0]
    
    block_device_mappings {
        device_name = "/dev/xvda"
        
        ebs {
        volume_size = 20
        volume_type = "gp3"
        encrypted   = true
        }
    }

    key_name = length(var.ssh_keys) > 0 ? var.ssh_keys[0] : null

    user_data = base64encode(templatefile("${path.module}/user_data.yaml", {
        cluster_name        = aws_eks_cluster.cluster.name
        cluster_endpoint    = aws_eks_cluster.cluster.endpoint
        cluster_ca_data     = aws_eks_cluster.cluster.certificate_authority[0].data
        cluster_cidr        = aws_eks_cluster.cluster.kubernetes_network_config[0].service_ipv4_cidr
        registry_mirror_url = var.registry_mirror_url
    }))
    
    metadata_options {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 2
    }

    tag_specifications {
        resource_type = "instance"
        tags = {
            Name = "${var.name}-eks-node"
        }
    }

    vpc_security_group_ids = [aws_security_group.eks_cluster_sg_allow_ssh.id]
}

resource "aws_eks_node_group" "node_group" {
    cluster_name    = aws_eks_cluster.cluster.name
    node_group_name = "${var.name}-eks-node-group-asg"
    node_role_arn   = aws_iam_role.eks_node_role.arn
    subnet_ids      = aws_eks_cluster.cluster.vpc_config[0].subnet_ids
    
    scaling_config {
        desired_size = 1
        max_size     = 3
        min_size     = 0
    }

    instance_types = var.worker_node_instance_types
  
    launch_template {
      id      = aws_launch_template.eks_node_group.id
      version = "$Latest"
    }
    
    tags = {
        Name = "${var.name}-eks-node-group-asg"
    }
}

