package compliance.policy.process.ensure_arguments_contain_key

import data.benchmark_data_adapter
import data.compliance.lib.assert
import data.compliance.lib.common as lib_common
import data.compliance.policy.process.data_adapter

process_args := data_adapter.process_args(benchmark_data_adapter.process_args_seperator)

finding(rule_evaluation) = result {
	# set result
	result := lib_common.generate_result_without_expected(
		lib_common.calculate_result(rule_evaluation),
		{"process_args": process_args},
	)
}

not_contains(entity) := assert.is_false(lib_common.contains_key(process_args, entity))

contains(entity) := lib_common.contains_key(process_args, entity)

apiserver_filter := data_adapter.is_kube_apiserver

controller_manager_filter := data_adapter.is_kube_controller_manager
