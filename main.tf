provider "aws" {
  region  = "${var.aws_region}"
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
}

#---------IAM---------

#S3 access

resource "aws_iam_instance_profile" "s3_access_profile" {
  name = "s3_access"
  role = "${aws_iam_role.s3_access_role.name}"
}

resource "aws_iam_role_policy" "s3_access_policy" {
  name = "s3_access_policy"
  role = "${aws_iam_role.s3_access_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action":"s3:*",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role" "s3_access_role" {
  name = "s3_access_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Action":"sts:AssumeRole",
    "Principal": {
      "Service": "ec2.amazonaws.com"
    },
    "Effect": "Allow",
    "Sid": ""
  }]
}
EOF
}

#------ VPC ------

resource "aws_vpc" "terra_vpc" {
  cidr_block           = "${var.vpc_cidr}"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags {
    Name = "terra_vpc"
  }
}

# Internet gateway

resource "aws_internet_gateway" "terra_internet_gateway" {
  vpc_id = "${aws_vpc.terra_vpc.id}"

  tags {
    Name = "terra_igw"
  }
}

# Route tables

resource "aws_route_table" "terra_public_rt" {
  vpc_id = "${aws_vpc.terra_vpc.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.terra_internet_gateway.id}"
  }

  tags {
    Name = "terra_public"
  }
}

resource "aws_default_route_table" "terra_private_rt" {
  default_route_table_id = "${aws_vpc.terra_vpc.default_route_table_id}"

  tags {
    Name = "terra_private"
  }
}

# Subnets

resource "aws_subnet" "terra_public1_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["public1"]}"
  map_public_ip_on_launch = true
  availability_zone       = "${data.aws_availability_zones.available.names[0]}"

  tags {
    Name = "terra_public1"
  }
}

resource "aws_subnet" "terra_public2_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["public2"]}"
  map_public_ip_on_launch = true
  availability_zone       = "${data.aws_availability_zones.available.names[1]}"

  tags {
    Name = "terra_public2"
  }
}

resource "aws_subnet" "terra_private1_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["private1"]}"
  map_public_ip_on_launch = false
  availability_zone       = "${data.aws_availability_zones.available.names[0]}"

  tags {
    Name = "terra_private1"
  }
}

resource "aws_subnet" "terra_private2_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["private2"]}"
  map_public_ip_on_launch = false
  availability_zone       = "${data.aws_availability_zones.available.names[1]}"

  tags {
    Name = "terra_private2"
  }
}

resource "aws_subnet" "terra_rds1_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["rds1"]}"
  map_public_ip_on_launch = false
  availability_zone       = "${data.aws_availability_zones.available.names[0]}"

  tags {
    Name = "terra_rds1"
  }
}

resource "aws_subnet" "terra_rds2_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["rds2"]}"
  map_public_ip_on_launch = false
  availability_zone       = "${data.aws_availability_zones.available.names[1]}"

  tags {
    Name = "terra_rds2"
  }
}

resource "aws_subnet" "terra_rds3_subnet" {
  vpc_id                  = "${aws_vpc.terra_vpc.id}"
  cidr_block              = "${var.cidrs["rds3"]}"
  map_public_ip_on_launch = false
  availability_zone       = "${data.aws_availability_zones.available.names[2]}"

  tags {
    Name = "terra_rds3"
  }
}

# rds subnet group

resource "aws_db_subnet_group" "terra_rds_subnetgroup" {
  name = "terra_rds_subnetgroup"

  subnet_ids = ["${aws_subnet.terra_rds1_subnet.id}",
    "${aws_subnet.terra_rds2_subnet.id}",
    "${aws_subnet.terra_rds3_subnet.id}",
  ]

  tags {
    Name = "terra_rds.sng"
  }
}

# Subnet Associations

resource "aws_route_table_association" "terra_public1_assoc" {
  subnet_id      = "${aws_subnet.terra_public1_subnet.id}"
  route_table_id = "${aws_route_table.terra_public_rt.id}"
}

resource "aws_route_table_association" "terra_public2_assoc" {
  subnet_id      = "${aws_subnet.terra_public2_subnet.id}"
  route_table_id = "${aws_route_table.terra_public_rt.id}"
}

resource "aws_route_table_association" "terra_private1_assoc" {
  subnet_id      = "${aws_subnet.terra_private1_subnet.id}"
  route_table_id = "${aws_default_route_table.terra_private_rt.id}"
}

resource "aws_route_table_association" "terra_private2_assoc" {
  subnet_id      = "${aws_subnet.terra_private2_subnet.id}"
  route_table_id = "${aws_default_route_table.terra_private_rt.id}"
}

# Security groups

resource "aws_security_group" "terra_dev_sg" {
  name        = "terra_dev_sg"
  description = "Used for access to the dev instance"
  vpc_id      = "${aws_vpc.terra_vpc.id}"

  # SSH rule

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.localip}"]
  }

  # HTTP rule

  ingress {
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
}

# Public Security Group

resource "aws_security_group" "terra_public_sg" {
  name        = "terra_public_sg"
  description = "Used for the elastic load balancer for public access"
  vpc_id      = "${aws_vpc.terra_vpc.id}"

  # HTTP rule

  ingress {
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
}

# Private SG

resource "aws_security_group" "terra_private_sg" {
  name        = "terra_private_sg"
  description = "Used for private instances"
  vpc_id      = "${aws_vpc.terra_vpc.id}"

  # Access from VPC

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["${var.vpc_cidr}"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS SG

resource "aws_security_group" "terra_rds_sg" {
  name        = "terra_rds_sg"
  description = "Used for RDS instances"
  vpc_id      = "${aws_vpc.terra_vpc.id}"

  # HTTP rule

  ingress {
    from_port = 3306
    to_port   = 3306
    protocol  = "tcp"

    security_groups = ["${aws_security_group.terra_dev_sg.id}",
      "${aws_security_group.terra_public_sg.id}",
      "${aws_security_group.terra_private_sg.id}",
    ]
  }
}

# VPC Endpoint for S3

resource "aws_vpc_endpoint" "terra_private_s3_endpoint" {
  vpc_id       = "${aws_vpc.terra_vpc.id}"
  service_name = "com.amazonaws.${var.aws_region}.s3"

  route_table_ids = ["${aws_vpc.terra_vpc.main_route_table_id}",
    "${aws_route_table.terra_public_rt.id}",
  ]

  policy = <<POLICY
{
  "Statement": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*",
      "Principal": "*"
    }
  ]
}
POLICY
}

#----- S3 code bucket ------

resource "random_id" "terra_code_bucket" {
  byte_length = 2
}

resource "aws_s3_bucket" "code" {
  bucket        = "terra-${random_id.terra_code_bucket.dec}"
  acl           = "private"
  force_destroy = true

  tags {
    Name = "code_bucket"
  }
}

#------ RDS --------

resource "aws_db_instance" "terra_db" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = "5.7.22"
  instance_class         = "${var.db_instance_class}"
  name                   = "${var.dbname}"
  username               = "${var.dbuser}"
  password               = "${var.dbpassword}"
  db_subnet_group_name   = "${aws_db_subnet_group.terra_rds_subnetgroup.name}"
  vpc_security_group_ids = ["${aws_security_group.terra_rds_sg.id}"]
  skip_final_snapshot    = true
}

#----- Dev Server -----

resource "aws_key_pair" "terra_auth" {
  key_name   = "${var.key_name}"
  public_key = "${file(var.public_key_path)}"
}

resource "aws_instance" "terra_dev" {
  instance_type          = "${var.dev_instance_type}"
  ami                    = "${var.dev_ami}"
  key_name               = "${aws_key_pair.terra_auth.id}"
  vpc_security_group_ids = ["${aws_security_group.terra_dev_sg.id}"]
  iam_instance_profile   = "${aws_iam_instance_profile.s3_access_profile.id}"
  subnet_id              = "${aws_subnet.terra_public1_subnet.id}"

  provisioner "local-exec" {
    command = <<EOD
cat <<EOF > aws_hosts
[dev]
${aws_instance.terra_dev.public_ip}
[dev:vars]
s3code=${aws_s3_bucket.code.bucket}

EOF
EOD
  }

  # the above may miss this line : "domain=${var.domain_name}"
  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${aws_instance.terra_dev.id} --profile thinh && ansible-playbook -i aws_hosts wordpress.yml"
  }

  tags {
    Name = "terra_dev"
  }
}

#----- Load balancer -----

resource "aws_elb" "terra_elb" {
  name = "terra-elb"

  subnets = ["${aws_subnet.terra_public1_subnet.id}",
    "${aws_subnet.terra_public2_subnet.id}",
  ]

  security_groups = ["${aws_security_group.terra_public_sg.id}"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = "${var.elb_healthy_threshold}"
    unhealthy_threshold = "${var.elb_unhealthy_threshold}"
    timeout             = "${var.elb_timeout}"
    target              = "TCP:80"
    interval            = "${var.elb_interval}"
  }

  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

  tags {
    Name = "terra_elb"
  }
}

#----- Goldern AMI -----

# random ami id

resource "random_id" "golden_ami" {
  byte_length = 3
}

# AMI

resource "aws_ami_from_instance" "terra_golden" {
  name               = "wp_ami-${random_id.golden_ami.b64}"
  source_instance_id = "${aws_instance.terra_dev.id}"

  provisioner "local-exec" {
    command = <<EOT
cat << EOF > userdata 
#!/bin/bash
/user/bin/aws s3 sync s3://${aws_s3_bucket.code.bucket} /var/www/html
/bin/touch /var/spool/cron/root
sudo /bin/echo '*/5 * * * * aws s3 sync s3://{aws_s3_bucket.code.bucket} /var/www/html >> /var/spool/cron/root'
EOF
EOT
  }
}

#----- Launch config -----
resource "aws_launch_configuration" "terra_lc" {
  name_prefix          = "terra_lc"
  image_id             = "${aws_ami_from_instance.terra_golden.id}"
  instance_type        = "${var.lc_instance_type}"
  security_groups      = ["${aws_security_group.terra_private_sg.id}"]
  iam_instance_profile = "${aws_iam_instance_profile.s3_access_profile.id}"
  key_name             = "${aws_key_pair.terra_auth.id}"
  user_data            = "${file("userdata")}"

  lifecycle {
    create_before_destroy = true
  }
}

#----- ASG -----
resource "aws_autoscaling_group" "terra_asg" {
  name                      = "asg-${aws_launch_configuration.terra_lc.id}"
  max_size                  = "${var.asg_max}"
  min_size                  = "${var.asg_min}"
  health_check_grace_period = "${var.asg_grace}"
  health_check_type         = "${var.asg_hct}"
  desired_capacity          = "${var.asg_cap}"
  force_delete              = true
  load_balancers            = ["${aws_elb.terra_elb.id}"]

  vpc_zone_identifier = ["${aws_subnet.terra_private1_subnet.id}",
    "${aws_subnet.terra_private2_subnet.id}",
  ]

  launch_configuration = "${aws_launch_configuration.terra_lc.name}"

  tag {
    key                 = "Name"
    value               = "wp_asg-instance"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_policy" "scaleup" {
  name                   = "scaleup"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = "${aws_autoscaling_group.terra_asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "scaleup" {
  alarm_name          = "scaleup"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "70"

  alarm_description = "Scale up when EC2 instances pass threshold"
  alarm_actions     = ["${aws_autoscaling_policy.scaleup.arn}"]

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.terra_asg.name}"
  }
}

resource "aws_autoscaling_policy" "scaledown" {
  name                   = "scaledown"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = "${aws_autoscaling_group.terra_asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "scaledown" {
  alarm_name          = "scaledown"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "30"

  alarm_description = "Scale down when EC2 instances pass threshold"
  alarm_actions     = ["${aws_autoscaling_policy.scaledown.arn}"]

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.terra_asg.name}"
  }
}
