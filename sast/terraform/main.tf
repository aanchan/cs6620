terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VPC
resource "aws_vpc" "sast_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "sast-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "sast_igw" {
  vpc_id = aws_vpc.sast_vpc.id

  tags = {
    Name = "sast-igw"
  }
}

# Public Subnets
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.sast_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "sast-public-1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.sast_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "sast-public-2"
  }
}

# Private Subnets
resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.sast_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "sast-private-1"
  }
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.sast_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "sast-private-2"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"
}

# NAT Gateway in public subnet 1
resource "aws_nat_gateway" "sast_nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_1.id

  tags = {
    Name = "sast-nat"
  }

  depends_on = [aws_internet_gateway.sast_igw]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.sast_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sast_igw.id
  }

  tags = {
    Name = "sast-rtb-public"
  }
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.sast_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.sast_nat.id
  }

  tags = {
    Name = "sast-rtb-private"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_1" {
  subnet_id      = aws_subnet.private_1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_2" {
  subnet_id      = aws_subnet.private_2.id
  route_table_id = aws_route_table.private.id
}

# ALB Security Group
resource "aws_security_group" "alb_sg" {
  name        = "sast-alb-sg"
  description = "Allow HTTP inbound to ALB"
  vpc_id      = aws_vpc.sast_vpc.id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
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
    Name = "sast-alb-sg"
  }
}

# EC2 Security Group
resource "aws_security_group" "ec2_sg" {
  name        = "sast-ec2-sg"
  description = "Allow traffic only from ALB"
  vpc_id      = aws_vpc.sast_vpc.id

  ingress {
    description     = "App port from ALB only"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sast-ec2-sg"
  }
}

# Target Group
resource "aws_lb_target_group" "sast_tg" {
  name     = "sast-target-group"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.sast_vpc.id

  health_check {
    path                = "/health"
    port                = "3000"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = {
    Name = "sast-tg"
  }
}

# Application Load Balancer
resource "aws_lb" "sast_alb" {
  name               = "sast-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  tags = {
    Name = "sast-alb"
  }
}

# ALB Listener
resource "aws_lb_listener" "sast_listener" {
  load_balancer_arn = aws_lb.sast_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sast_tg.arn
  }
}

# User Data Script
locals {
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y docker
    systemctl start docker
    systemctl enable docker
    docker pull spicehandler/sast-app:latest
    docker run -d \
      -p 3000:3000 \
      --name sast-app \
      --restart unless-stopped \
      spicehandler/sast-app:latest
  EOF
}

# EC2 Instance 1
resource "aws_instance" "sast_1" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_1.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = "LabInstanceProfile"
  user_data              = local.user_data

  tags = {
    Name = "sast-server-1"
  }
}

# EC2 Instance 2
resource "aws_instance" "sast_2" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_2.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = "LabInstanceProfile"
  user_data              = local.user_data

  tags = {
    Name = "sast-server-2"
  }
}

# Register EC2 instances with Target Group
resource "aws_lb_target_group_attachment" "sast_1" {
  target_group_arn = aws_lb_target_group.sast_tg.arn
  target_id        = aws_instance.sast_1.id
  port             = 3000
}

resource "aws_lb_target_group_attachment" "sast_2" {
  target_group_arn = aws_lb_target_group.sast_tg.arn
  target_id        = aws_instance.sast_2.id
  port             = 3000
}

# Outputs
output "alb_dns_name" {
  description = "ALB DNS name — share with teammates"
  value       = aws_lb.sast_alb.dns_name
}

output "sast_endpoint" {
  description = "Full SAST service endpoint"
  value       = "http://${aws_lb.sast_alb.dns_name}/scan/code"
}

output "sast_health_endpoint" {
  description = "Health check endpoint"
  value       = "http://${aws_lb.sast_alb.dns_name}/health"
}