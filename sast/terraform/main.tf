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

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "sast_sg" {
  name        = "sast-security-group"
  description = "Security group for SAST backend service"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["71.227.224.139/32"]
  }

  ingress {
    description = "SAST service port from my IP"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["71.227.224.139/32"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "sast_server" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = "t2.micro"
  subnet_id                   = tolist(data.aws_subnets.public.ids)[0]
  vpc_security_group_ids      = [aws_security_group.sast_sg.id]
  associate_public_ip_address = true
  iam_instance_profile        = "LabInstanceProfile"
  key_name                    = "vockey"
  

  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y docker
    systemctl start docker
    systemctl enable docker
    docker pull spicehandler/sast-app:latest
    docker run -d -p 3000:3000 --name sast-app --restart unless-stopped spicehandler/sast-app:latest
  EOF

  tags = {
    Name = "sast-backend"
  }
}

output "sast_public_ip" {
  description = "Public IP of the SAST backend instance"
  value       = aws_instance.sast_server.public_ip
}

output "sast_health_endpoint" {
  description = "Health check endpoint"
  value       = "http://${aws_instance.sast_server.public_ip}:3000/health"
}