package compliance.cis_aws.rules.cis_2_1_2

import data.compliance.lib.common

# Ensure S3 Bucket Policy is set to deny HTTP requests
finding = result {
    # set result
	result := common.generate_result_without_expected(
		common.calculate_result(rule_evaluation),
		input.resource
	)
}

rule_evaluation {
    bucket_policy := input.resource.bucketpolicies[_]
    statement := bucket_policy.document.value.Statement[_]
    statement.Condition.Bool["aws:SecureTransport"][0] == "false"
    statement.Action[0] == "s3:*"
    statement.Effect == "Deny"
    statement.Principal == "*"
} else = false {
    true
}
