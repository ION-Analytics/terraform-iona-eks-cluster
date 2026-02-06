resource "aws_iam_role" "eks_cluster_role" {
    name = "${var.name}-eks-cluster-role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {
                    Service = "eks.amazonaws.com"
                }
            },
        ]
    })
} 
resource "aws_iam_role_policy_attachment" "eks_cluster_role_attachment" {
    role       = aws_iam_role.eks_cluster_role.name
    policy_arn = aws_iam_policy.eks_cluster_policy.arn
}

resource "aws_iam_policy" "eks_cluster_policy" {
    name        = "${var.name}-eks-cluster-policy"
    description = "EKS Cluster Policy"
    policy      = data.aws_iam_policy_document.eks_cluster_policy.json
}

data "aws_iam_policy_document" "eks_cluster_policy" {
  statement {
    sid       = "AmazonEKSClusterPolicy"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:UpdateAutoScalingGroup",
      "ec2:AttachVolume",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateRoute",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:CreateVolume",
      "ec2:DeleteRoute",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteVolume",
      "ec2:DescribeInstances",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications",
      "ec2:DescribeVpcs",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeAvailabilityZones",
      "ec2:DetachVolume",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyVolume",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeInstanceTopology",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
      "elasticloadbalancing:AttachLoadBalancerToSubnets",
      "elasticloadbalancing:ConfigureHealthCheck",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateLoadBalancerListeners",
      "elasticloadbalancing:CreateLoadBalancerPolicy",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancerListeners",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancerPolicies",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DetachLoadBalancerFromSubnets",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
      "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
      "kms:DescribeKey",
    ]
  }

  statement {
    sid       = "AmazonEKSClusterPolicySLRCreate"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["iam:CreateServiceLinkedRole"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.amazonaws.com"]
    }
  }

  statement {
    sid       = "AmazonEKSClusterPolicyENIDelete"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteNetworkInterface"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/eks:eni:owner"
      values   = ["amazon-vpc-cni"]
    }
  }
}


resource "aws_iam_role" "eks_node_role" {
    name = "${var.name}-eks-node-role"
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {
                    Service = "ec2.amazonaws.com"
                }
            },
        ]
    })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_role_AmazonEKSWorkerNodePolicy" {
    role       = aws_iam_role.eks_node_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_role_AmazonEKS_CNI_Policy" {
    role       = aws_iam_role.eks_node_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_role_AmazonEC2ContainerRegistryReadOnly" {
    role       = aws_iam_role.eks_node_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy_attachment" {
    role       = aws_iam_role.eks_node_role.name
    policy_arn = aws_iam_policy.eks_worker_node_policy.arn
}

resource "aws_iam_policy" "eks_worker_node_policy" {
    name        = "${var.name}-eks-worker-node-policy"
    description = "EKS Worker Node Policy"
    policy      = data.aws_iam_policy_document.aws_eks_node_group_policy.json
}

data "aws_iam_policy_document" "aws_eks_node_group_policy" {
  statement {
    sid       = "SharedSecurityGroupRelatedPermissions"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:DescribeInstances",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:DeleteSecurityGroup",
    ]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/eks"
      values   = ["*"]
    }
  }

  statement {
    sid       = "EKSCreatedSecurityGroupRelatedPermissions"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:DescribeInstances",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:DeleteSecurityGroup",
    ]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/eks:nodegroup-name"
      values   = ["*"]
    }
  }

  statement {
    sid       = "LaunchTemplateRelatedPermissions"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:DeleteLaunchTemplate",
      "ec2:CreateLaunchTemplateVersion",
    ]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/eks:nodegroup-name"
      values   = ["*"]
    }
  }

  statement {
    sid       = "AutoscalingRelatedPermissions"
    effect    = "Allow"
    resources = ["arn:aws:autoscaling:*:*:*:autoScalingGroupName/eks-*"]

    actions = [
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:DeleteAutoScalingGroup",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:PutLifecycleHook",
      "autoscaling:PutNotificationConfiguration",
      "autoscaling:EnableMetricsCollection",
      "autoscaling:PutScheduledUpdateGroupAction",
      "autoscaling:ResumeProcesses",
      "autoscaling:SuspendProcesses",
    ]
  }

  statement {
    sid       = "AllowAutoscalingToCreateSLR"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["iam:CreateServiceLinkedRole"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["autoscaling.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowASGCreationByEKS"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:CreateOrUpdateTags",
      "autoscaling:CreateAutoScalingGroup",
    ]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:TagKeys"

      values = [
        "eks",
        "eks:cluster-name",
        "eks:nodegroup-name",
      ]
    }
  }

  statement {
    sid       = "AllowPassRoleToAutoscaling"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["iam:PassRole"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["autoscaling.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowPassRoleToEC2"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["iam:PassRole"]

    condition {
      test     = "StringEqualsIfExists"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  statement {
    sid       = "PermissionsToManageResourcesForNodegroups"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "iam:GetRole",
      "ec2:CreateLaunchTemplate",
      "ec2:DescribeInstances",
      "iam:GetInstanceProfile",
      "ec2:DescribeLaunchTemplates",
      "autoscaling:DescribeAutoScalingGroups",
      "ec2:CreateSecurityGroup",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:RunInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:GetConsoleOutput",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSubnets",
      "ec2:DescribeCapacityReservations",
    ]
  }

  statement {
    sid       = "PermissionsToCreateAndManageInstanceProfiles"
    effect    = "Allow"
    resources = ["arn:aws:iam::*:instance-profile/eks-*"]

    actions = [
      "iam:CreateInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:AddRoleToInstanceProfile",
    ]
  }

  statement {
    sid       = "PermissionsToDeleteEKSAndKubernetesTags"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DeleteTags"]

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "aws:TagKeys"

      values = [
        "eks",
        "eks:cluster-name",
        "eks:nodegroup-name",
        "kubernetes.io/cluster/*",
      ]
    }
  }

  statement {
    sid       = "PermissionsForManagedNodegroupsAutoRepair"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:RebootInstances"]

    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/eks:nodegroup-name"
      values   = ["*"]
    }
  }

  statement {
    sid    = "PermissionsToCreateEKSAndKubernetesTags"
    effect = "Allow"

    resources = [
      "arn:*:ec2:*:*:security-group/*",
      "arn:*:ec2:*:*:launch-template/*",
    ]

    actions = ["ec2:CreateTags"]

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "aws:TagKeys"

      values = [
        "eks",
        "eks:cluster-name",
        "eks:nodegroup-name",
        "kubernetes.io/cluster/*",
      ]
    }
  }

  statement {
    sid    = "AllowTaggingEC2ResourcesOnlyDuringInstanceCreation"
    effect = "Allow"

    resources = [
      "arn:*:ec2:*:*:instance/*",
      "arn:*:ec2:*:*:volume/*",
      "arn:*:ec2:*:*:network-interface/*",
    ]

    actions = ["ec2:CreateTags"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances"]
    }

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "aws:TagKeys"

      values = [
        "eks",
        "eks:cluster-name",
        "eks:nodegroup-name",
        "kubernetes.io/cluster/*",
      ]
    }
  }
}
