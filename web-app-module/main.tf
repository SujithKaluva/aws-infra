
# Create a VPC
resource "aws_vpc" "webapp_vpc" {
  cidr_block = var.cidr_name
  tags = {
    Name = var.vpc_tag_name
  }
}

# Create a VPC_2
resource "aws_vpc" "webapp_vpc_2" {
  cidr_block = var.cidr_name
  tags = {
    Name = var.vpc_tag_name_2
  }
}

# Create a IG
resource "aws_internet_gateway" "webapp_igw" {
  vpc_id = aws_vpc.webapp_vpc.id
  tags = {
    Name = "internet_gateway_1"
  }
}

# Create a IG 2
resource "aws_internet_gateway" "webapp_igw_2" {
  vpc_id = aws_vpc.webapp_vpc_2.id
  tags = {
    Name = "internet_gateway_2"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}
output "availability_zones" {
  value = data.aws_availability_zones.available.names
}

//Routes
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.webapp_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.webapp_igw.id
  }
  tags = {
    Name = "${var.vpc_tag_name}_publicroutetable_1"
  }
}

resource "aws_route_table" "public_rt_2" {
  vpc_id = aws_vpc.webapp_vpc_2.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.webapp_igw_2.id
  }
  tags = {
    Name = "${var.vpc_tag_name_2}_publicroutetable_2"
  }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.webapp_vpc.id
  tags = {
    Name = "${var.vpc_tag_name}_privateroutetable_1"
  }
}
resource "aws_route_table" "private_rt_2" {
  vpc_id = aws_vpc.webapp_vpc_2.id
  tags = {
    Name = "${var.vpc_tag_name_2}_privateroutetable_2"
  }
}


# resource "aws_route" "public_rt_internet_gateway" {
#   route_table_id = aws_route_table.public_rt.id
#   cidr_block = "0.0.0.0/0"
#   gateway_id = aws_internet_gateway.webapp_igw.id
# }


resource "aws_subnet" "public_subnet" {
  count             = 3
  cidr_block        = cidrsubnet(aws_vpc.webapp_vpc.cidr_block, 8, count.index)
  vpc_id            = aws_vpc.webapp_vpc.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Type = var.vpc_tag_name
    Name = "vpc1_public_subnet_${count.index + 1}"
  }
}

resource "aws_subnet" "public_subnet_2" {
  count             = 3
  cidr_block        = cidrsubnet(aws_vpc.webapp_vpc_2.cidr_block, 8, count.index)
  vpc_id            = aws_vpc.webapp_vpc_2.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Type = var.vpc_tag_name_2
    Name = "vpc2_public_subnet_${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnet" {
  count             = 3
  cidr_block        = cidrsubnet(aws_vpc.webapp_vpc.cidr_block, 8, count.index + 3)
  vpc_id            = aws_vpc.webapp_vpc.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Type = var.vpc_tag_name
    Name = "vpc1_private_subnet_${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnet_2" {
  count             = 3
  cidr_block        = cidrsubnet(aws_vpc.webapp_vpc_2.cidr_block, 8, count.index + 3)
  vpc_id            = aws_vpc.webapp_vpc_2.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Type = var.vpc_tag_name_2
    Name = "vpc2_private_subnet_${count.index + 1}"
  }
}

locals {
  public_subnet_ids = aws_subnet.public_subnet.*.id
  public_subnet_ids_2 = aws_subnet.public_subnet_2.*.id
  private_subnet_ids = aws_subnet.private_subnet.*.id
  private_subnet_ids_2 = aws_subnet.private_subnet_2.*.id
}

resource "aws_route_table_association" "public_subnet_association" {
  count = length(local.public_subnet_ids)
  subnet_id = local.public_subnet_ids[count.index]
  route_table_id = aws_route_table.public_rt.id
}
resource "aws_route_table_association" "public_subnet_association_2" {
  count = length(local.public_subnet_ids_2)
  subnet_id = local.public_subnet_ids_2[count.index]
  route_table_id = aws_route_table.public_rt_2.id
}

resource "aws_route_table_association" "private_subnet_association" {
  count = length(local.private_subnet_ids)
  subnet_id = local.private_subnet_ids[count.index]
  route_table_id = aws_route_table.private_rt.id
}
resource "aws_route_table_association" "private_subnet_association_2" {
  count = length(local.private_subnet_ids_2)
  subnet_id = local.private_subnet_ids_2[count.index]
  route_table_id = aws_route_table.private_rt_2.id
}


