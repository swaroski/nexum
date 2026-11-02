# Supplier ABC's policy for XYZ's agents, in Rego. Equivalent to
# examples/cross-company/abc-policy.yaml.
#
# Nexum asks OPA only after the delegation chain, proof, chain authority and
# trust checks passed, so this policy can only narrow what they allow.
# `input` is Nexum's AuthorizationRequest: subject, actor, organization,
# action, resource, purpose, delegation_chain, authority, context.value, ...
package nexum.authz

import rego.v1

depth := count(input.delegation_chain) - 1

value := object.get(input.context, "value", null)

decision := {"outcome": "DENY", "policy_id": "abc-supplier-rego", "rule_id": "not-xyz"} if {
	input.organization != "xyz.com"
} else := {"outcome": "DENY", "policy_id": "abc-supplier-rego", "rule_id": "no-payments"} if {
	input.action in {"payment.execute", "customer.export"}
} else := {"outcome": "DENY", "policy_id": "abc-supplier-rego", "rule_id": "sub-agents-read-only"} if {
	depth > 0
	not input.action in {"inventory.read", "pricing.read"}
} else := {"outcome": "ALLOW", "policy_id": "abc-supplier-rego", "rule_id": "reads"} if {
	input.action in {"inventory.read", "pricing.read"}
	startswith(input.resource, "supplier://abc/")
} else := {"outcome": "ALLOW", "policy_id": "abc-supplier-rego", "rule_id": "quote-auto"} if {
	input.action == "quote.create"
	is_number(value)
	value <= 100000
} else := {"outcome": "REQUIRE_APPROVAL", "policy_id": "abc-supplier-rego", "rule_id": "quote-approval"} if {
	input.action == "quote.create"
	is_number(value)
	value > 100000
} else := {"outcome": "DENY", "policy_id": "abc-supplier-rego", "rule_id": "default-deny"}
