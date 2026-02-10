variable "release" {
    description = "Release information"
    type        = map   
}

variable "platform_config" {
    description = "Platform configuration"
    type        = map   
}

variable "name" {
    description = "Name of the EKS cluster"
    type        = string
    default     = "default"
}
variable "kubernetes_version" {
    description = "Kubernetes version for the EKS cluster"
    type        = string
    default     = "1.35"
}
variable "ssh_keys" {
    description = "SSH key names for EC2 instances"
    type        = list(string)
    default     = []
}
variable "internal_vpc_cidr" {
    description = "CIDR block for the internal VPC"
    type        = string
    default     = "172.20.0.0/16"
}

variable "node_private_subnets" {
    description = "List of private subnet IDs for the EKS node group"
    type        = list(string)
    default     = ["172.20.0.0/18", "172.20.64.0/18", "172.20.128.0/18"]
}

variable "iam_role_eks_admin_access" {
    description = "IAM Role ARN for EKS cluster admin access"
    type        = string
}

variable "inbound_cidr_blocks" {
    description = "List of CIDR blocks for inbound traffic to EKS cluster security group"
    type        = list(string)
}

variable "woker_node_instance_types" {
    description = "List of EC2 instance types for EKS worker nodes"
    type        = list(string)
    default     = ["t3.medium"]
}

variable "deployment_teams" {
    description = "List of teams with deployment access to the EKS cluster"
    type        = list(string)
    default     = []
}

variable "registry_mirror_url" {
    description = "Container registry mirror URL for Docker Hub images"
    type        = string
}