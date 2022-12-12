package compliance.policy.aws_s3.data_adapter

is_s3 {
	input.subType == "aws-s3"
}

default encryption_algorithm = null
encryption_algorithm = input.resource.Encryption.ApplyServerSideEncryptionByDefault.SSEAlgorithm
