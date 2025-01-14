package compliance.cis_eks.rules.cis_3_2_9

import data.compliance.cis_eks.data_adapter
import data.kubernetes_common.test_data
import data.lib.test

violations {
	test.assert_fail(finding) with input as rule_input("--event-qps 10")
	test.assert_fail(finding) with input as rule_input_with_external("--event-qps 10", create_process_config(0))
	test.assert_fail(finding) with input as rule_input_with_external("--event-qps 10", create_process_config(10))
	test.assert_fail(finding) with input as rule_input_with_external("", create_process_config(10))
	test.assert_fail(finding) with input as rule_input("")
}

test_violation {
	violations with data.benchmark_data_adapter as data_adapter
}

passes {
	test.assert_pass(finding) with input as rule_input("--event-qps 0")
	test.assert_pass(finding) with input as rule_input_with_external("--event-qps 0", create_process_config(0))
	test.assert_pass(finding) with input as rule_input_with_external("--event-qps 0", create_process_config(10))
	test.assert_pass(finding) with input as rule_input_with_external("", create_process_config(0))
}

test_pass {
	passes with data.benchmark_data_adapter as data_adapter
}

test_not_evaluated {
	not finding with input as test_data.process_input("some_process", []) with data.benchmark_data_adapter as data_adapter
}

rule_input(argument) = test_data.process_input_with_external_data("kubelet", [argument], {})

rule_input_with_external(argument, external_data) = test_data.process_input_with_external_data("kubelet", [argument], external_data)

create_process_config(eventRecordQPS) = {"config": {"eventRecordQPS": eventRecordQPS}}
