terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "lstoll"

    workspaces {
      name = "lambdaid"
    }
  }
}

provider "aws" {
  version = "~> 2.0"

  region = "us-east-1"
}
