package compliance.cis_eks.rules.cis_3_2_2

import data.compliance.cis_eks.data_adapter
import data.kubernetes_common.test_data
import data.lib.test

violations {
	test.assert_fail(finding) with input as rule_input("")
	test.assert_fail(finding) with input as rule_input("--authorization-mode AlwaysAllow")
	test.assert_fail(finding) with input as rule_input_with_external("--authorization-mode AlwaysAllow", create_process_config("AlwaysAllow"))
	test.assert_fail(finding) with input as rule_input_with_external("", create_process_config("AlwaysAllow"))
}

test_violations {
	violations with data.benchmark_data_adapter as data_adapter
}

passes {
	test.assert_pass(finding) with input as rule_input("--authorization-mode Webhook")
	test.assert_pass(finding) with input as rule_input_with_external("--authorization-mode Webhook", create_process_config("AlwaysAllow"))
	test.assert_pass(finding) with input as rule_input_with_external("", create_process_config("Webhook"))
}

test_pass {
	passes with data.benchmark_data_adapter as data_adapter
}

test_not_evaluated {
	not finding with input as test_data.process_input("some_process", []) with data.benchmark_data_adapter as data_adapter
}

rule_input(argument) = test_data.process_input("kubelet", [argument])

rule_input_with_external(argument, external_data) = test_data.process_input_with_external_data("kubelet", [argument], external_data)

create_process_config(authz_mode) = {"config": {"authorization": {
	"mode": authz_mode,
	"webhook": {
		"cacheAuthorizedTTL": "0s",
		"cacheUnauthorizedTTL": "0s",
	},
}}}
