provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "vpc_1" {
  cidr_block = var.vpc_cidr[0]
  tags = {
    Name = "vpc_1"
  }
}

resource "aws_internet_gateway" "internet_gateway_1" {
  vpc_id = aws_vpc.vpc_1.id
  tags = {
    Name = "internet_gateway_1"
  }
}

resource "aws_subnet" "public_subnets_1" {
  count                   = length(data.aws_availability_zones.available.names) > 2 ? 3 : 2
  cidr_block              = "${var.subnet_prefix_1}.${count.index + 1}.${var.subnet_suffix}"
  vpc_id                  = aws_vpc.vpc_1.id
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Type = var.public_tag
    Name = "${var.public_subnet_name}_${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnets_1" {
  count             = length(data.aws_availability_zones.available.names) > 2 ? 3 : 2
  cidr_block        = "${var.subnet_prefix_1}.${count.index + 4}.${var.subnet_suffix}"
  vpc_id            = aws_vpc.vpc_1.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Type = var.private_tag
    Name = "${var.private_subnet_name}_${count.index + 1}"
  }
}

resource "aws_route_table" "public_route_table_1" {
  vpc_id = aws_vpc.vpc_1.id
  route {
    cidr_block = var.public_route_table_cidr
    gateway_id = aws_internet_gateway.internet_gateway_1.id
  }
  tags = {
    Name = "${var.public_tag}_routetable_1"
  }
}

resource "aws_route_table" "private_route_table_1" {
  vpc_id = aws_vpc.vpc_1.id
  tags = {
    Name = "${var.private_tag}_routetable_1"
  }
}

resource "aws_route_table_association" "public_subnets_association_1" {
  count          = length(aws_subnet.public_subnets_1.*.id)
  subnet_id      = aws_subnet.public_subnets_1[count.index].id
  route_table_id = aws_route_table.public_route_table_1.id
}

resource "aws_route_table_association" "private_subnets_association_1" {
  count          = length(aws_subnet.private_subnets_1.*.id)
  subnet_id      = aws_subnet.private_subnets_1[count.index].id
  route_table_id = aws_route_table.private_route_table_1.id
}

# Application Security Group
resource "aws_security_group" "application" {
  name_prefix = "application-"
  description = "Security group for WebApp"
  vpc_id      = aws_vpc.vpc_1.id
  # ingress {
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = var.app_port
  #   to_port     = var.app_port
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application-security-group"
  }
}

resource "aws_security_group_rule" "application_ssh_ingress" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.load_balancer_sg.id
}

resource "aws_security_group_rule" "application_web_ingress" {
  type                     = "ingress"
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.load_balancer_sg.id
}


# Database Security Group
resource "aws_security_group" "database_security_group" {
  name_prefix = "database-"
  description = "Security group for RDS Instance"
  vpc_id      = aws_vpc.vpc_1.id
  tags = {
    Name = "database-security-group"
  }
}

# Add an inbound rule to the RDS security group to allow traffic from the EC2 security group
resource "aws_security_group_rule" "rds_ingress" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.database_security_group.id
  source_security_group_id = aws_security_group.application.id
}

# Add an outbound rule to the RDS security group to allow traffic from the EC2 security group
resource "aws_security_group_rule" "rds_egress" {
  type                     = "egress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.database_security_group.id
  source_security_group_id = aws_security_group.application.id
}

# Add an inbound rule to the EC2 security group to allow traffic to the RDS security group
resource "aws_security_group_rule" "ec2_ingress" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = aws_security_group.application.id
  source_security_group_id = aws_security_group.database_security_group.id
}

#Security Group for Load Balancer
resource "aws_security_group" "load_balancer_sg" {
  name_prefix = "load_balancer_sg"
  description = "Security group for load balancer to access web application"
  vpc_id      = aws_vpc.vpc_1.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "load-balancer-security-group"
  }
}

#Create Key Pair
resource "aws_key_pair" "ec2keypair" {
  key_name   = "ec2AMI"
  public_key = file("~/.ssh/ec2.pub")
}

# # Create EC2 Instance
# resource "aws_instance" "EC2-CSYE6225" {
#   ami                     = var.aws_ami
#   instance_type           = "t2.micro"
#   disable_api_termination = false
#   ebs_optimized           = false
#   root_block_device {
#     volume_size           = 50
#     volume_type           = "gp2"
#     delete_on_termination = true
#   }
#   vpc_security_group_ids = [aws_security_group.application.id]
#   subnet_id              = aws_subnet.public_subnets_1[0].id
#   key_name               = aws_key_pair.ec2keypair.key_name
#   iam_instance_profile   = aws_iam_instance_profile.s3_access_instance_profile.name
#   user_data              = <<EOF
# #!/bin/bash
# echo "[Unit]
# Description=Webapp Service
# After=network.target

# [Service]
# Environment="DB_HOST=${element(split(":", aws_db_instance.rds_instance.endpoint), 0)}"
# Environment="DB_USER=${aws_db_instance.rds_instance.username}"
# Environment="DB_PASSWORD=${aws_db_instance.rds_instance.password}"
# Environment="DB_DATABASE=${aws_db_instance.rds_instance.db_name}"
# Environment="AWS_BUCKET_NAME=${aws_s3_bucket.sujithawsbucket.bucket}"
# Environment="AWS_REGION=${var.aws_region}"
# Type=simple
# User=ec2-user
# WorkingDirectory=/home/ec2-user/webapp
# ExecStart=/usr/bin/node server.js
# Restart=on-failure

# [Install]
# WantedBy=multi-user.target" > /etc/systemd/system/webapp.service
# sudo systemctl daemon-reload
# sudo systemctl start webapp.service
# sudo systemctl enable webapp.service
# sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl  -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/cloudwatch-config.json -s
# EOF
#   tags = {
#     Name = "WebApp EC2 Instance"
#   }
# }

# RDS Instance
resource "aws_db_instance" "rds_instance" {
  db_name                = var.rds_db_name
  identifier             = var.rds_identifier
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  multi_az               = false
  username               = var.rds_username
  password               = var.rds_password
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.database_security_group.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.rds_parameter_group.name
  allocated_storage      = 10
  skip_final_snapshot    = true
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rdskms.arn

  tags = {
    Name = "csye6225_rds_instance"
  }
}

resource "aws_kms_key" "rdskms" {
  # customer_master_key_spec = "RSA_2048"
  # key_usage                = "ENCRYPT_DECRYPT"
  description = "Encrypting RDS instance"
  policy = jsonencode({
    Id = "ebskeypolicy"
    Statement = [
      {
        Action = "kms:*"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }

        Resource = "*"
        Sid      = "Enable IAM User Permissions"
      },
    ]
    Version = "2012-10-17"
  })
}

# DB subnet group
resource "aws_db_subnet_group" "rds_subnet_group" {
  name        = "rds_subnet_group"
  subnet_ids  = [aws_subnet.private_subnets_1[1].id, aws_subnet.private_subnets_1[2].id]
  description = "Subnet group for the RDS instance"
}

# RDS Parameter Group
resource "aws_db_parameter_group" "rds_parameter_group" {
  name_prefix = "rds-parameter-group"
  family      = "mysql8.0"
  description = "RDS DB parameter group for MySQL 8.0"

  parameter {
    name  = "max_connections"
    value = "100"
  }

  parameter {
    name  = "innodb_buffer_pool_size"
    value = "268435456"
  }
}

resource "random_uuid" "image_uuid" {}

#S3 Bucket
resource "aws_s3_bucket" "sujithawsbucket" {
  bucket = "sujithawsbucket-${random_uuid.image_uuid.result}"
  # acl           = "private"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "access_bucket" {
  bucket = aws_s3_bucket.sujithawsbucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_server_side_encryption_configuration" "my_bucket_encryption" {
  bucket = aws_s3_bucket.sujithawsbucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "my_bucket_lifecycle" {
  bucket = aws_s3_bucket.sujithawsbucket.id
  rule {
    id     = "transition-objects-to-standard-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_iam_instance_profile" "s3_access_instance_profile" {
  name = "s3_access_instance_profile"
  role = aws_iam_role.s3_access_role.name

  tags = {
    Terraform = "true"
  }
}

resource "aws_iam_role" "s3_access_role" {
  name = "EC2-CSYE6225"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Terraform = "true"
  }
}

resource "aws_iam_policy" "s3_access_policy" {
  name        = "WebAppS3"
  description = "Policy to allow access to S3 bucket"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:s3:::${aws_s3_bucket.sujithawsbucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.sujithawsbucket.bucket}/*"
        ]
      }
    ]
    }
  )
}
resource "aws_iam_role_policy_attachment" "s3_access_role_policy_attachment" {
  policy_arn = aws_iam_policy.s3_access_policy.arn
  role       = aws_iam_role.s3_access_role.name
}

resource "aws_iam_policy_attachment" "web-app-attach-cloudwatch" {
  name       = "attach-cloudwatch-server-policy-ec2"
  roles      = [aws_iam_role.s3_access_role.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Create Route53 Zone
data "aws_route53_zone" "hosted_zone" {
  name         = var.domain_name
  private_zone = false
}

# Create Route53 record
resource "aws_route53_record" "hosted_zone_record" {
  zone_id = data.aws_route53_zone.hosted_zone.zone_id
  name    = var.domain_name
  type    = "A"
  # ttl     = "60"
  # records = [aws_instance.EC2-CSYE6225.public_ip]
  # records = [aws_lb.application.dns_name]

  alias {
    name                   = aws_lb.application.dns_name
    zone_id                = aws_lb.application.zone_id
    evaluate_target_health = true
  }
}

resource "aws_kms_key" "ebskms" {
  description             = "Symmetric customer-managed KMS key for EBS"
  deletion_window_in_days = 10
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Sid" : "Allow service-linked role use of the customer managed key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:CreateGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ] }
  )

}
resource "aws_launch_template" "EC2-CSYE6225" {
  name                    = "EC2-CSYE6225"
  image_id                = var.aws_ami
  instance_type           = "t2.micro"
  key_name                = aws_key_pair.ec2keypair.key_name
  disable_api_termination = false
  ebs_optimized           = false
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 50
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ebskms.arn
    }
  }
  network_interfaces {
    associate_public_ip_address = true
    subnet_id                   = aws_subnet.public_subnets_1[0].id
    security_groups             = [aws_security_group.application.id]
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.s3_access_instance_profile.name
  }
  user_data = base64encode(<<EOF
#!/bin/bash
echo "[Unit]
Description=Webapp Service
After=network.target

[Service]
Environment="DB_HOST=${element(split(":", aws_db_instance.rds_instance.endpoint), 0)}"
Environment="DB_USER=${aws_db_instance.rds_instance.username}"
Environment="DB_PASSWORD=${aws_db_instance.rds_instance.password}"
Environment="DB_DATABASE=${aws_db_instance.rds_instance.db_name}"
Environment="AWS_BUCKET_NAME=${aws_s3_bucket.sujithawsbucket.bucket}"
Environment="AWS_REGION=${var.aws_region}"
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/webapp
ExecStart=/usr/bin/node server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/webapp.service
sudo systemctl daemon-reload
sudo systemctl start webapp.service
sudo systemctl enable webapp.service
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl  -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/cloudwatch-config.json -s
EOF
  )
}

resource "aws_autoscaling_group" "webapp_autoscaling_group" {
  name             = "webapp_autoscaling_group"
  max_size         = 3
  min_size         = 1
  desired_capacity = 1
  # launch_configuration = aws_launch_template.EC2-CSYE6225.id
  launch_template {
    id      = aws_launch_template.EC2-CSYE6225.id
    version = "$Latest"
  }

  vpc_zone_identifier = [aws_subnet.public_subnets_1[0].id]

  target_group_arns = [aws_lb_target_group.application.arn]

  default_cooldown = 60
  # count            = 3
  # Tags for the instances created by the ASG
  tag {
    key                 = "Name"
    value               = "WEBAPP Instance" # - ${format("%02d", count.index + 1)}"
    propagate_at_launch = true
  }
}

#Autoscaling policies - Scale up
resource "aws_autoscaling_policy" "scale_up_policy" {
  name                   = "autoscaling_up_policy"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = "1"
  autoscaling_group_name = aws_autoscaling_group.webapp_autoscaling_group.name
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
}

#Autoscaling policies - Scale down
resource "aws_autoscaling_policy" "scale_down_policy" {
  name                   = "autoscaling_down_policy"
  policy_type            = "SimpleScaling"
  scaling_adjustment     = "-1"
  autoscaling_group_name = aws_autoscaling_group.webapp_autoscaling_group.name
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
}

#Alarm for Scale up
resource "aws_cloudwatch_metric_alarm" "alarm_scale_up" {
  alarm_name          = "alarm_scale_up"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  period              = 120
  evaluation_periods  = 2
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.webapp_autoscaling_group.name
  }
  actions_enabled = true
  alarm_actions   = [aws_autoscaling_policy.scale_up_policy.arn]
}

#Alarm for scale down
resource "aws_cloudwatch_metric_alarm" "alarm_scale_down" {
  alarm_name          = "alarm_scale_down"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  threshold           = 3
  comparison_operator = "LessThanOrEqualToThreshold"
  period              = 120
  evaluation_periods  = 2
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.webapp_autoscaling_group.name
  }
  actions_enabled = true
  alarm_actions   = [aws_autoscaling_policy.scale_down_policy.arn]
}

# Create an Application Load Balancer resource
resource "aws_lb" "application" {
  name               = "webapp-application-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_sg.id]

  subnets = aws_subnet.public_subnets_1[*].id

  enable_deletion_protection = false
}

data "aws_acm_certificate" "certi" {
  domain   = var.domain_name
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "application" {
  # Configure the HTTPS listener on port 443
  load_balancer_arn = aws_lb.application.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.certi.arn

  # Configure the target group for the listener
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.application.arn
  }
}

# Create a target group for the load balancer to forward traffic to
resource "aws_lb_target_group" "application" {
  name_prefix = "tg-grp"
  port        = var.app_port
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.vpc_1.id

  # Health check configuration for the target group
  health_check {
    path                = var.health_check
    port                = "traffic-port"
    protocol            = "HTTP"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
  }
}

data "aws_caller_identity" "current" {}
