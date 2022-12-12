package compliance.policy.aws_s3.ensure_encryption_at_rest

import data.compliance.lib.common as lib_common
import data.compliance.policy.aws_s3.data_adapter

default rule_evaluation = false

# Verify that all listeners has an SSL Certificate
rule_evaluation = true {
	data_adapter.encryption_algorithm == "AES256"
}

rule_evaluation = true {
	data_adapter.encryption_algorithm == "aws:kms"
}

finding = result {
	data_adapter.is_s3

	result := lib_common.generate_result_without_expected(
		lib_common.calculate_result(rule_evaluation),
		{
			"SSSEAlgorithm": data_adapter.encryption_algorithm,
		},
	)
}
