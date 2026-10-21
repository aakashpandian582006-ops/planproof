terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"
}

# Real AWS Stateful Resource (PostgreSQL RDS Database)
resource "aws_db_instance" "prod_db" {
  allocated_storage   = 20
  db_name             = "planproof_db"
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.micro"
  username            = "postgres"
  password            = "Password123!"
  skip_final_snapshot = true
}
