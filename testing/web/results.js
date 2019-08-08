function lsw_summary_graph_click_test_run(table_id, summary_test_run) {
    console.log("click-test_run", table_id, summary_test_run)
    window.location = "../" + summary_test_run.directory
}

function results(div_id, json_file) {
    d3.json(json_file, function(error, results) {

	if (error) {
	    return console.warn(error)
	}

	var columns = [
	    {
		title: "Test",
		value: function(result) {
		    return result.test_name
		},
		html: function(result) {
		    return ("<a href=\""
			    + result.test_name
			    + "\">"
			    + result.test_name
			    + "</a>")
		},
	    },
	    {
		title: "Kind",
		value: function(result) {
		    return (result.test_kind !== undefined
			    ? result.test_kind
			    : "")
		},
	    },
	    {
		title: "Status",
		value: function(result) {
		    return (result.test_status !== undefined
			    ? result.test_status
			    : result.expected_result !== undefined
			    ? result.expected_result
			    : "")
		},
	    },
	    {
		title: "Result",
	    },
	    {
		title: "Errors and Warnings",
		html: function(result) {
		    if (!result || result.result == "untested") {
			return ""
		    }
		    var test_host_names = (result.test_host_names !== undefined
					   ? result.test_host_names
					   : result.host_names !== undefined
					   ? result.host_names
					   : null)
		    if (!test_host_names) {
			return ""
		    }
		    var br = false
		    var html = ""
		    test_host_names.forEach(function(host) {
			if (br) {
			    html += "<br/>"
			}
			br = true
			html += host + ":"
			if (result.errors[host] === undefined
			    || result.errors[host].length == 0) {
			    html += "passed"
			    return
			}
			sep = ""
			result.errors[host].forEach(function(error) {
			    html += sep
			    sep = ", "
			    var href = null
			    var value = ""
			    if (error == "passed") {
				value = "passed"
			    } else if (error == "baseline-missing") {
				// Probably a new test.
				value = "previous-missing"
			    } else if (error == "output-different"
				       || error == "output-whitespace") {
				href = result.output_directory + "/" + host + ".console.diff"
				value = error
			    } else if (error == "output-unchecked") {
				href = result.output_directory + "/" + host + ".console.txt"
				value = error
			    } else if (error == "output-truncated") {
				href = result.output_directory + "/" + host + ".console.verbose.txt"
				value = error
			    } else if (error == "baseline-passed") {
				// The current test failed, but the
				// previous test passed.
				value = "previous-passed"
			    } else if (error == "baseline-failed") {
				// The current test passed, but the
				// previous test failed.
				href = result.baseline_output_directory + "/" + host + ".console.diff"
				value = "previous-failed"
			    } else if (error == "baseline-different"
				       || error == "baseline-whitespace") {
				// The current and previous tests
				// fail, but in different ways.  Ideal
				// would be to show the diff between
				// this and the old test.  Showing the
				// old diff might be helpful.
				href = result.baseline_output_directory + "/" + host + ".console.diff"
				value = "previous-different"
			    } else if (error == "EXPECTATION"
				       || error == "ASSERTION") {
				href = result.output_directory + "/" + host + ".pluto.log.gz"
				value = error
			    } else {
				href = result.output_directory
				value = error
			    }
			    if (href) {
				html += "<a href=\"" + href + "\">" + value + "</a>"
			    } else {
				html += value
			    }
			})
		    })
		    return html
		},
	    },
	    {
		title: "Boot time",
	    },
	    {
		title: "Script time",
	    },
	    {
		title: "Run Time",
		value: function(result) {
		    return (result.runtime !== undefined
			    ? result.runtime
			    : result.total_time !== undefined
			    ? result.total_time
			    : "")
		},
	    },
	]

	lsw_table({
	    id: div_id,
	    data: results,
	    columns: columns,
	})
    })
}
