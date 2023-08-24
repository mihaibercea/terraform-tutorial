terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.6"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "eu-central-1"
}

resource "aws_vpc" "VPC-Terraform" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = "true"
 
  tags = {
    Name = "VPC-Terraform"
  }
}

variable "public_subnet_cidrs" {
 type        = list(string)
 description = "Public Subnet CIDR values"
 default     = ["10.0.1.0/24", "10.0.2.0/24"]
}
 
variable "private_subnet_cidrs" {
 type        = list(string)
 description = "Private Subnet CIDR values"
 default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "azs" {
 type        = list(string)
 description = "Availability Zones"
 default     = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
}

resource "aws_subnet" "public_subnets" {
 count      = length(var.public_subnet_cidrs)
 vpc_id     = aws_vpc.VPC-Terraform.id
 cidr_block = element(var.public_subnet_cidrs, count.index)
 availability_zone = element(var.azs, count.index)
 map_public_ip_on_launch= "true"
 
 tags = {
   Name = "Public Subnet ${count.index + 1}"
 }
}
 
resource "aws_subnet" "private_subnets" {
 count      = length(var.private_subnet_cidrs)
 vpc_id     = aws_vpc.VPC-Terraform.id
 cidr_block = element(var.private_subnet_cidrs, count.index)
 availability_zone = element(var.azs, count.index)
 map_public_ip_on_launch= "true"
 
 tags = {
   Name = "Private Subnet ${count.index + 1}"
 }
}

resource "aws_internet_gateway" "gw" {
    vpc_id = aws_vpc.VPC-Terraform.id

    tags = {
        Name = "gw"
    }
}

resource "aws_route_table" "r" {
    vpc_id = aws_vpc.VPC-Terraform.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.gw.id
    }
    tags = {
        Name = "r"
    }
}

resource "aws_route_table_association" "a" {
    count      = length(aws_subnet.public_subnets)  
    subnet_id  = aws_subnet.public_subnets[count.index].id 
    route_table_id = aws_route_table.r.id  
}

resource "aws_eip" "nat_eips" {
  count = length(var.public_subnet_cidrs)
  vpc = true
}

resource "aws_nat_gateway" "nat_gateways" {
  count = length(var.public_subnet_cidrs)

  subnet_id     = aws_subnet.public_subnets[count.index].id
  allocation_id = aws_eip.nat_eips[count.index].id

  tags = {
    Name = "NAT Gateway ${count.index + 1}"
  }
}

resource "aws_route_table" "r_nat" {
    count = length(var.public_subnet_cidrs)
    vpc_id = aws_vpc.VPC-Terraform.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_nat_gateway.nat_gateways[count.index].id        
    }
    tags = {
        Name = "route table private nat"
    }
}

resource "aws_route_table_association" "nat_private" {
    count = length(var.private_subnet_cidrs)
    
    subnet_id = aws_subnet.private_subnets[count.index].id 
    route_table_id = aws_route_table.r_nat[count.index].id

}

resource "tls_private_key" "instance_private_keys" {
    count = length(var.private_subnet_cidrs)
    algorithm = "RSA"
    rsa_bits = 4096
}

resource "local_file" "private_keys" {
    count = length(var.private_subnet_cidrs)
    content = tls_private_key.instance_private_keys[count.index].private_key_pem
    filename = "private_key${count.index + 1}.pem"
    file_permission = 0400
}

resource "aws_key_pair" "instance_keys" {
    count = length(var.private_subnet_cidrs)
    key_name = "instance${count.index + 1}"
    public_key = tls_private_key.instance_private_keys[count.index].public_key_openssh
}

resource "aws_security_group" "private_subnet_sg" {
  count       = length(var.private_subnet_cidrs)
  name        = "private-sg-${count.index + 1}"
  description = "Security Group for Private Subnet ${count.index + 1}"
  vpc_id      = aws_vpc.VPC-Terraform.id

  # Inbound rule to allow connections from the Instance Connect endpoint's security group
  ingress {
    from_port   = 22  # Assuming SSH, change this if you are using a different port
    to_port     = 22
    protocol    = "tcp"
    security_groups = [aws_security_group.instance_connect_sg.id]
  }

  # Outbound rule for internet access through NAT gateway
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# resource "aws_ec2_instance_connect_endpoint" "instance_connect" {
#   description = "Instance Connect Endpoint"
#   name_prefix = "InstanceConnect-"

#   # Allow inbound traffic to the endpoint
#   network_origin {
#     source = "0.0.0.0/0"  # You can restrict this to specific IP ranges if needed
#   }
# }

resource "aws_security_group" "instance_connect_sg" {
  name_prefix = "InstanceConnectSG-"
  description = "Security Group for Instance Connect Endpoint"
  vpc_id      = aws_vpc.VPC-Terraform.id

  # Inbound rule for Instance Connect
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]    
  }
#   egress {
#     from_port   = 22  # Assuming SSH, change this if you are using a different port
#     to_port     = 22
#     protocol    = "tcp"
#     security_groups = [aws_security_group.private_subnet_sg[*].id]
#   }
}

resource "aws_security_group_rule" "allow_outbound_ssh_rule" {
  count       = length(var.private_subnet_cidrs)
  security_group_id        = aws_security_group.instance_connect_sg.id
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  type                     = "egress"
  source_security_group_id = aws_security_group.private_subnet_sg[count.index].id
}


# resource "aws_ec2_instance_connect_endpoint " "instance_connect" {
#   vpc_id            = aws_vpc.VPC-Terraform.id
# #   service_name      = "ec2-instance-connect.eu-central-1.amazonaws.com"
# #   vpc_endpoint_type = "Gateway"

#   security_group_ids = [
#     aws_security_group.instance_connect_sg.id,
#   ]

#   private_dns_enabled = true
# }

# resource "aws_vpc_endpoint" "ec2" {
#   vpc_id            = aws_vpc.VPC-Terrafor.id
#   service_name      = "ec2-instance-connect.eu-central-1.amazonaws.com"
#   vpc_endpoint_type = "Interface"

#   security_group_ids = [
#     aws_security_group.sg1.id,
#   ]

#   private_dns_enabled = true
# }

resource "aws_instance" "private_instances" {
  count         = length(var.private_subnet_cidrs)
  ami           = "ami-0c4c4bd6cf0c5fe52"  # Replace with your desired AMI ID
  instance_type = "t2.micro"     # Change to your desired instance type
  subnet_id     = aws_subnet.private_subnets[count.index].id
  key_name      = aws_key_pair.instance_keys[count.index].key_name
  security_groups = [aws_security_group.private_subnet_sg[count.index].id]
  user_data = file("linux.sh")

  # Other instance configuration...
}

variable "health_check" {
   type = map(string)
   default = {
      "timeout"  = "10"
      "interval" = "20"
      "path"     = "/"
      "port"     = "80"
      "unhealthy_threshold" = "2"
      "healthy_threshold" = "3"
    }
}

resource "aws_lb_target_group" "tg-nginx" {
   count         = length(var.private_subnet_cidrs)
   name               = "tg-nginx${count.index + 1}"
   target_type        = "instance"
   port               = 80
   protocol           = "HTTP"
   vpc_id             = aws_vpc.VPC-Terraform.id
   health_check {
      healthy_threshold   = var.health_check["healthy_threshold"]
      interval            = var.health_check["interval"]
      unhealthy_threshold = var.health_check["unhealthy_threshold"]
      timeout             = var.health_check["timeout"]
      path                = var.health_check["path"]
      port                = var.health_check["port"]
  }
}

resource "aws_lb_target_group_attachment" "tg_attachments" {
  count            = length(var.private_subnet_cidrs)
  target_group_arn = aws_lb_target_group.tg-nginx[count.index].arn

  target_id = aws_instance.private_instances[count.index].id
}

resource "aws_security_group" "lba_sg" {

  vpc_id      = aws_vpc.VPC-Terraform.id

  # Inbound rule for Instance Connect
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]    
  }
  egress {
    from_port   = 80  # Assuming SSH, change this if you are using a different port
    to_port     = 80
    protocol    = "tcp"
    security_groups = [for sg in aws_security_group.private_subnet_sg : sg.id]
  }
}

resource "aws_security_group_rule" "allow_inbound_from_lba" {
  count          = length(var.private_subnet_cidrs)
  type           = "ingress"
  from_port      = 80  # Adjust the port as needed
  to_port        = 80  # Adjust the port as needed
  protocol       = "tcp"
  security_group_id = aws_security_group.private_subnet_sg[count.index].id
  source_security_group_id = aws_security_group.lba_sg.id
}


resource "aws_lb" "LBA_resource" {
  name               = "example-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = aws_subnet.public_subnets[*].id
  security_groups    = [aws_security_group.lba_sg.id]

  enable_deletion_protection = false
}

resource "aws_lb_listener" "lb_listener_http" {
  load_balancer_arn = aws_lb.LBA_resource.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"      
    }
  }
}

# Rule 1: Forward traffic to "nginx1" for requests with path "/nginx1"
resource "aws_lb_listener_rule" "lb_listener_rules" {
  count            = length(var.private_subnet_cidrs)
  listener_arn = aws_lb_listener.lb_listener_http.arn 

  action {
    type = "forward"

    target_group_arn = aws_lb_target_group.tg-nginx[count.index].arn

  }

  condition {
    path_pattern {
      values = ["/nginx${count.index + 1}/"]
    }
  }
}

# # Rule 2: Forward traffic to "nginx2" for requests with path "/nginx2"
# resource "aws_lb_listener_rule" "lb_listener_rule_nginx2" {
#   listener_arn = aws_lb_listener.lb_listener_http.arn

#   action {
#     type = "forward"

#     target_group {
#       target_group_arn = aws_lb_target_group.tg-nginx.arn
#     }
#   }

#   condition {
#     path_pattern {
#       values = ["/nginx2"]
#     }
#   }
# }

# resource "aws_lb_listener_rule" "nginx1_rule" {
#   listener_arn = aws_lb.example.arn
#   action {
#     type = "fixed-response"

#     fixed_response {
#       content_type = "text/plain"
#       status_code  = "200"
#       content      = "Redirecting to nginx1"
#     }
#   }

#   condition {
#     path_pattern {
#       values = ["/nginx1"]
#     }
#   }
# }

# resource "aws_lb_listener_rule" "nginx2_rule" {
#   listener_arn = aws_lb.LBA_resource.arn
#   action {
#     type = "fixed-response"

#     fixed_response {
#       content_type = "text/plain"
#       status_code  = "200"
#       content      = "Redirecting to nginx2"
#     }
#   }

#   condition {
#     path_pattern {
#       values = ["/nginx2"]
#     }
#   }
# }
