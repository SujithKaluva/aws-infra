# aws-infra

# Terraform Infrastructure as Code (IaC) for AWS

This Terraform code creates a VPC with multiple public and private subnets across multiple availability zones. It also creates internet gateways and route tables to enable the subnets to communicate with each other and to the internet.

## Prerequisites
- Install Terraform by following the [official installation instructions](https://learn.hashicorp.com/tutorials/terraform/install-cli).
- Ensure that you have valid AWS credentials for the account where you wish to deploy the infrastructure.

## Usage
1. Clone the repository and navigate to the root directory.
2. Run `terraform init` to initialize the Terraform environment.
3. Run `terraform plan` to preview the infrastructure changes.
4. Run `terraform apply` to create the infrastructure.


## Clean up
To delete the infrastructure created by this code, run `terraform destroy` after navigating to the root directory.

## Certificate Import
Command to import the Certificate
`aws acm import-certificate --certificate file://certificate.crt --certificate-chain file://CertificateChain.pem --private-key file://Private.key`