resource "aws_eks_access_entry" "admin_access" {
  for_each = toset(var.deployment_teams)
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = var.iam_role_eks_admin_access
  type              = "STANDARD"
}

resource "aws_eks_access_policy_association" "admin_access" {
    cluster_name  = aws_eks_cluster.cluster.name
    policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    principal_arn = var.iam_role_eks_admin_access

    access_scope {
        type       = "cluster"
    }
}

resource "aws_eks_access_entry" "deployment_team_access" {
  for_each = toset(var.deployment_teams)
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${each.value}"
  type              = "STANDARD"
}

resource "aws_eks_access_policy_association" "deployment_access" {
    for_each = toset(var.deployment_teams)
    cluster_name  = aws_eks_cluster.cluster.name
    policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${each.value}"

    access_scope {
      type  = "cluster"
    }
    depends_on = [ aws_eks_access_entry.deployment_team_access ]
}