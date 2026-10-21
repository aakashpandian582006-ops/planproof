package rules

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Severity defines the severity level of a rule violation.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Violation represents an individual rule violation found during plan analysis.
type Violation struct {
	RuleID          string   `json:"rule_id"`
	RuleName        string   `json:"rule_name"`
	Severity        Severity `json:"severity"`
	ResourceAddress string   `json:"resource_address"`
	ResourceType    string   `json:"resource_type"`
	Description     string   `json:"description"`
	Remediation     string   `json:"remediation"`
	RiskScore       int      `json:"risk_score"`
}

// ResourceChange represents a resource change parsed from Terraform plan JSON.
type ResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Change  struct {
		Actions []string               `json:"actions"`
		Before  map[string]interface{} `json:"before"`
		After   map[string]interface{} `json:"after"`
	} `json:"change"`
}

// Rule defines the interface for an IaC security and compliance rule.
type Rule interface {
	ID() string
	Name() string
	DefaultSeverity() Severity
	Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation
}

// RuleEngine evaluates a set of rules against Terraform plan resource changes.
type RuleEngine struct {
	rules []Rule
}

// NewRuleEngine initializes a RuleEngine with all standard enterprise AWS rules.
func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{
		rules: make([]Rule, 0),
	}

	engine.Register(&StatefulDestructionRule{})
	engine.Register(&S3EncryptionRule{})
	engine.Register(&S3PublicACLRule{})
	engine.Register(&OpenSSHRule{})
	engine.Register(&OpenRDPRule{})
	engine.Register(&IAMWildcardRule{})

	return engine
}

// Register adds a new rule to the engine.
func (e *RuleEngine) Register(r Rule) {
	e.rules = append(e.rules, r)
}

// Evaluate runs all registered rules against the provided resource changes.
func (e *RuleEngine) Evaluate(resourceChanges []ResourceChange) []Violation {
	var violations []Violation

	for i := range resourceChanges {
		rc := &resourceChanges[i]
		for _, r := range e.rules {
			vs := r.Evaluate(rc, resourceChanges)
			if len(vs) > 0 {
				violations = append(violations, vs...)
			}
		}
	}

	return violations
}

// ============================================================================
// RULE IMPLEMENTATIONS
// ============================================================================

// --- 1. Stateful Destruction Rule (STATE-001) ---
type StatefulDestructionRule struct{}

func (r *StatefulDestructionRule) ID() string               { return "STATE-001" }
func (r *StatefulDestructionRule) Name() string             { return "Stateful Resource Destruction Guard" }
func (r *StatefulDestructionRule) DefaultSeverity() Severity { return SeverityCritical }

func (r *StatefulDestructionRule) Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation {
	statefulTypes := map[string]bool{
		"aws_db_instance":              true,
		"aws_s3_bucket":                true,
		"aws_dynamodb_table":           true,
		"aws_elasticache_cluster":      true,
		"azurerm_postgresql_server":    true,
		"google_sql_database_instance": true,
	}

	if !statefulTypes[rc.Type] {
		return nil
	}

	isDestructive := false
	for _, action := range rc.Change.Actions {
		if action == "destroy" || action == "delete" {
			isDestructive = true
			break
		}
	}

	if !isDestructive {
		return nil
	}

	return []Violation{
		{
			RuleID:          r.ID(),
			RuleName:        r.Name(),
			Severity:        SeverityCritical,
			ResourceAddress: rc.Address,
			ResourceType:    rc.Type,
			Description:     fmt.Sprintf("Stateful resource '%s' (%s) is scheduled for DESTRUCTION without disaster recovery validation.", rc.Address, rc.Type),
			Remediation:     fmt.Sprintf("Add 'lifecycle { prevent_destroy = true }' to '%s' block or enable deletion protection.", rc.Address),
			RiskScore:       50,
		},
	}
}

// --- 2. S3 Bucket Missing Server-Side Encryption (AWS-S3-001) ---
type S3EncryptionRule struct{}

func (r *S3EncryptionRule) ID() string               { return "AWS-S3-001" }
func (r *S3EncryptionRule) Name() string             { return "S3 Bucket Missing Server-Side Encryption" }
func (r *S3EncryptionRule) DefaultSeverity() Severity { return SeverityHigh }

func (r *S3EncryptionRule) Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation {
	if rc.Type != "aws_s3_bucket" {
		return nil
	}

	// Only evaluate if resource is being created or updated
	if !isCreateOrUpdate(rc.Change.Actions) {
		return nil
	}

	after := rc.Change.After
	if after == nil {
		return nil
	}

	// Check inline server_side_encryption_configuration
	hasInlineEncryption := false
	if ssec, ok := after["server_side_encryption_configuration"]; ok && ssec != nil {
		if list, ok := ssec.([]interface{}); ok && len(list) > 0 {
			for _, item := range list {
				if m, ok := item.(map[string]interface{}); ok {
					if rule, ok := m["rule"]; ok && rule != nil {
						hasInlineEncryption = true
						break
					}
				}
			}
		}
	}

	if hasInlineEncryption {
		return nil
	}

	// Check if separate aws_s3_bucket_server_side_encryption_configuration exists in plan
	bucketName := getStringVal(after, "bucket")
	for _, other := range allResources {
		if other.Type == "aws_s3_bucket_server_side_encryption_configuration" && isCreateOrUpdate(other.Change.Actions) {
			otherAfter := other.Change.After
			if otherAfter != nil {
				targetBucket := getStringVal(otherAfter, "bucket")
				if targetBucket != "" && (targetBucket == bucketName || targetBucket == rc.Address || strings.Contains(other.Address, rc.Name)) {
					return nil
				}
			}
		}
	}

	return []Violation{
		{
			RuleID:          r.ID(),
			RuleName:        r.Name(),
			Severity:        SeverityHigh,
			ResourceAddress: rc.Address,
			ResourceType:    rc.Type,
			Description:     fmt.Sprintf("S3 bucket '%s' does not have server-side encryption (SSE) enabled. Data at rest is vulnerable to unauthorized exposure.", rc.Address),
			Remediation:     fmt.Sprintf("Configure 'server_side_encryption_configuration' block or 'aws_s3_bucket_server_side_encryption_configuration' with AES256 or aws:kms for '%s'.", rc.Address),
			RiskScore:       25,
		},
	}
}

// --- 3. S3 Public ACL Rule (AWS-S3-002) ---
type S3PublicACLRule struct{}

func (r *S3PublicACLRule) ID() string               { return "AWS-S3-002" }
func (r *S3PublicACLRule) Name() string             { return "S3 Bucket Public ACL Allowed" }
func (r *S3PublicACLRule) DefaultSeverity() Severity { return SeverityCritical }

func (r *S3PublicACLRule) Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation {
	if rc.Type != "aws_s3_bucket" && rc.Type != "aws_s3_bucket_acl" {
		return nil
	}

	if !isCreateOrUpdate(rc.Change.Actions) {
		return nil
	}

	after := rc.Change.After
	if after == nil {
		return nil
	}

	acl := strings.ToLower(getStringVal(after, "acl"))
	if acl == "public-read" || acl == "public-read-write" || acl == "website" {
		return []Violation{
			{
				RuleID:          r.ID(),
				RuleName:        r.Name(),
				Severity:        SeverityCritical,
				ResourceAddress: rc.Address,
				ResourceType:    rc.Type,
				Description:     fmt.Sprintf("S3 resource '%s' grants public access via ACL '%s'. Anyone on the public internet can read/modify bucket objects.", rc.Address, acl),
				Remediation:     fmt.Sprintf("Set bucket ACL to 'private' and apply 'aws_s3_bucket_public_access_block' to '%s'.", rc.Address),
				RiskScore:       50,
			},
		}
	}

	return nil
}

// --- 4. Open Ingress SSH (0.0.0.0/0 on port 22) (AWS-SG-001) ---
type OpenSSHRule struct{}

func (r *OpenSSHRule) ID() string               { return "AWS-SG-001" }
func (r *OpenSSHRule) Name() string             { return "Security Group Ingress Allows Open SSH Access (0.0.0.0/0)" }
func (r *OpenSSHRule) DefaultSeverity() Severity { return SeverityCritical }

func (r *OpenSSHRule) Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation {
	if !isCreateOrUpdate(rc.Change.Actions) {
		return nil
	}

	after := rc.Change.After
	if after == nil {
		return nil
	}

	switch rc.Type {
	case "aws_security_group":
		ingressRules := getSliceVal(after, "ingress")
		for _, ir := range ingressRules {
			if m, ok := ir.(map[string]interface{}); ok {
				if isRuleExposingPort(m, 22) {
					return []Violation{
						{
							RuleID:          r.ID(),
							RuleName:        r.Name(),
							Severity:        SeverityCritical,
							ResourceAddress: rc.Address,
							ResourceType:    rc.Type,
							Description:     fmt.Sprintf("Security group '%s' allows inbound SSH traffic (port 22) from the public internet (0.0.0.0/0).", rc.Address),
							Remediation:     fmt.Sprintf("Restrict SSH ingress in '%s' to specific internal CIDR ranges or an administrative VPN gateway.", rc.Address),
							RiskScore:       50,
						},
					}
				}
			}
		}

	case "aws_security_group_rule":
		ruleType := strings.ToLower(getStringVal(after, "type"))
		if ruleType == "ingress" && isRuleExposingPort(after, 22) {
			return []Violation{
				{
					RuleID:          r.ID(),
					RuleName:        r.Name(),
					Severity:        SeverityCritical,
					ResourceAddress: rc.Address,
					ResourceType:    rc.Type,
					Description:     fmt.Sprintf("Security group rule '%s' allows unrestricted SSH ingress (port 22) from 0.0.0.0/0.", rc.Address),
					Remediation:     fmt.Sprintf("Restrict CIDR blocks in '%s' to authorized network addresses instead of 0.0.0.0/0.", rc.Address),
					RiskScore:       50,
				},
			}
		}

	case "aws_vpc_security_group_ingress_rule":
		if isVpcIngressExposingPort(after, 22) {
			return []Violation{
				{
					RuleID:          r.ID(),
					RuleName:        r.Name(),
					Severity:        SeverityCritical,
					ResourceAddress: rc.Address,
					ResourceType:    rc.Type,
					Description:     fmt.Sprintf("VPC security group ingress rule '%s' exposes port 22 directly to 0.0.0.0/0.", rc.Address),
					Remediation:     fmt.Sprintf("Update 'cidr_ipv4' in '%s' to point to a trusted bastion or corporate subnet.", rc.Address),
					RiskScore:       50,
				},
			}
		}
	}

	return nil
}

// --- 5. Open Ingress RDP (0.0.0.0/0 on port 3389) (AWS-SG-002) ---
type OpenRDPRule struct{}

func (r *OpenRDPRule) ID() string               { return "AWS-SG-002" }
func (r *OpenRDPRule) Name() string             { return "Security Group Ingress Allows Open RDP Access (0.0.0.0/0)" }
func (r *OpenRDPRule) DefaultSeverity() Severity { return SeverityHigh }

func (r *OpenRDPRule) Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation {
	if !isCreateOrUpdate(rc.Change.Actions) {
		return nil
	}

	after := rc.Change.After
	if after == nil {
		return nil
	}

	switch rc.Type {
	case "aws_security_group":
		ingressRules := getSliceVal(after, "ingress")
		for _, ir := range ingressRules {
			if m, ok := ir.(map[string]interface{}); ok {
				if isRuleExposingPort(m, 3389) {
					return []Violation{
						{
							RuleID:          r.ID(),
							RuleName:        r.Name(),
							Severity:        SeverityHigh,
							ResourceAddress: rc.Address,
							ResourceType:    rc.Type,
							Description:     fmt.Sprintf("Security group '%s' allows inbound Windows RDP traffic (port 3389) from the public internet (0.0.0.0/0).", rc.Address),
							Remediation:     fmt.Sprintf("Restrict RDP ingress in '%s' to secure management networks or use AWS Systems Manager Fleet Manager.", rc.Address),
							RiskScore:       35,
						},
					}
				}
			}
		}

	case "aws_security_group_rule":
		ruleType := strings.ToLower(getStringVal(after, "type"))
		if ruleType == "ingress" && isRuleExposingPort(after, 3389) {
			return []Violation{
				{
					RuleID:          r.ID(),
					RuleName:        r.Name(),
					Severity:        SeverityHigh,
					ResourceAddress: rc.Address,
					ResourceType:    rc.Type,
					Description:     fmt.Sprintf("Security group rule '%s' allows unrestricted RDP ingress (port 3389) from 0.0.0.0/0.", rc.Address),
					Remediation:     fmt.Sprintf("Restrict CIDR blocks in '%s' to authorized network addresses instead of 0.0.0.0/0.", rc.Address),
					RiskScore:       35,
				},
			}
		}

	case "aws_vpc_security_group_ingress_rule":
		if isVpcIngressExposingPort(after, 3389) {
			return []Violation{
				{
					RuleID:          r.ID(),
					RuleName:        r.Name(),
					Severity:        SeverityHigh,
					ResourceAddress: rc.Address,
					ResourceType:    rc.Type,
					Description:     fmt.Sprintf("VPC security group ingress rule '%s' exposes RDP port 3389 to 0.0.0.0/0.", rc.Address),
					Remediation:     fmt.Sprintf("Update 'cidr_ipv4' in '%s' to point to an internal management subnet.", rc.Address),
					RiskScore:       35,
				},
			}
		}
	}

	return nil
}

// --- 6. IAM Policy Wildcards (AWS-IAM-001) ---
type IAMWildcardRule struct{}

func (r *IAMWildcardRule) ID() string               { return "AWS-IAM-001" }
func (r *IAMWildcardRule) Name() string             { return "IAM Policy Grants Overly Permissive Wildcard Permissions" }
func (r *IAMWildcardRule) DefaultSeverity() Severity { return SeverityHigh }

func (r *IAMWildcardRule) Evaluate(rc *ResourceChange, allResources []ResourceChange) []Violation {
	iamTypes := map[string]bool{
		"aws_iam_policy":       true,
		"aws_iam_role_policy":  true,
		"aws_iam_user_policy":  true,
		"aws_iam_group_policy": true,
	}

	if !iamTypes[rc.Type] {
		return nil
	}

	if !isCreateOrUpdate(rc.Change.Actions) {
		return nil
	}

	after := rc.Change.After
	if after == nil {
		return nil
	}

	policyVal, ok := after["policy"]
	if !ok || policyVal == nil {
		return nil
	}

	policyDoc, err := parsePolicyDocument(policyVal)
	if err != nil || policyDoc == nil {
		return nil
	}

	rawStatements, ok := policyDoc["Statement"]
	if !ok || rawStatements == nil {
		return nil
	}

	var statements []map[string]interface{}
	switch st := rawStatements.(type) {
	case []interface{}:
		for _, s := range st {
			if sm, ok := s.(map[string]interface{}); ok {
				statements = append(statements, sm)
			}
		}
	case map[string]interface{}:
		statements = append(statements, st)
	}

	var violations []Violation
	for _, stmt := range statements {
		effect := strings.ToLower(getStringVal(stmt, "Effect"))
		if effect != "allow" {
			continue
		}

		actions := extractStrings(stmt["Action"])
		resources := extractStrings(stmt["Resource"])

		hasWildcardAction := false
		hasFullWildcardAction := false
		for _, act := range actions {
			act = strings.TrimSpace(act)
			if act == "*" || act == "*:*" {
				hasWildcardAction = true
				hasFullWildcardAction = true
				break
			}
			if strings.HasSuffix(act, ":*") || strings.Contains(act, "*") {
				hasWildcardAction = true
			}
		}

		hasWildcardResource := false
		for _, res := range resources {
			res = strings.TrimSpace(res)
			if res == "*" {
				hasWildcardResource = true
				break
			}
		}

		if hasFullWildcardAction && hasWildcardResource {
			violations = append(violations, Violation{
				RuleID:          r.ID(),
				RuleName:        r.Name(),
				Severity:        SeverityCritical,
				ResourceAddress: rc.Address,
				ResourceType:    rc.Type,
				Description:     fmt.Sprintf("IAM policy '%s' grants unrestricted admin permissions with wildcard ('Action: *', 'Resource: *').", rc.Address),
				Remediation:     fmt.Sprintf("Follow least privilege for '%s': replace wildcard '*' with specific required IAM actions and resource ARNs.", rc.Address),
				RiskScore:       50,
			})
			break // Avoid duplicate reports for same policy
		} else if hasWildcardAction && hasWildcardResource {
			violations = append(violations, Violation{
				RuleID:          r.ID(),
				RuleName:        r.Name(),
				Severity:        SeverityHigh,
				ResourceAddress: rc.Address,
				ResourceType:    rc.Type,
				Description:     fmt.Sprintf("IAM policy '%s' grants broad wildcard actions ('%v') across all resources ('*').", rc.Address, actions),
				Remediation:     fmt.Sprintf("Scope permissions in '%s' to specific API actions and explicit resource ARNs.", rc.Address),
				RiskScore:       30,
			})
			break
		}
	}

	return violations
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func isCreateOrUpdate(actions []string) bool {
	for _, a := range actions {
		if a == "create" || a == "update" {
			return true
		}
	}
	return false
}

func getStringVal(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getSliceVal(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.([]interface{}); ok {
			return s
		}
	}
	return nil
}

func getIntVal(m map[string]interface{}, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return int(val), true
	case int:
		return val, true
	case string:
		if i, err := strconv.Atoi(val); err == nil {
			return i, true
		}
	}
	return 0, false
}

func isRuleExposingPort(ruleMap map[string]interface{}, targetPort int) bool {
	cidrs := extractStrings(ruleMap["cidr_blocks"])
	ipv6Cidrs := extractStrings(ruleMap["ipv6_cidr_blocks"])

	isOpen := false
	for _, c := range cidrs {
		if c == "0.0.0.0/0" {
			isOpen = true
			break
		}
	}
	if !isOpen {
		for _, c := range ipv6Cidrs {
			if c == "::/0" {
				isOpen = true
				break
			}
		}
	}

	if !isOpen {
		return false
	}

	proto := strings.ToLower(getStringVal(ruleMap, "protocol"))
	if proto == "-1" {
		return true
	}

	fromPort, hasFrom := getIntVal(ruleMap, "from_port")
	toPort, hasTo := getIntVal(ruleMap, "to_port")

	if hasFrom && hasTo {
		if fromPort == 0 && toPort == 0 {
			return true
		}
		if targetPort >= fromPort && targetPort <= toPort {
			return true
		}
	}

	return false
}

func isVpcIngressExposingPort(after map[string]interface{}, targetPort int) bool {
	cidrIpv4 := getStringVal(after, "cidr_ipv4")
	cidrIpv6 := getStringVal(after, "cidr_ipv6")

	if cidrIpv4 != "0.0.0.0/0" && cidrIpv6 != "::/0" {
		return false
	}

	proto := strings.ToLower(getStringVal(after, "ip_protocol"))
	if proto == "-1" {
		return true
	}

	fromPort, hasFrom := getIntVal(after, "from_port")
	toPort, hasTo := getIntVal(after, "to_port")

	if hasFrom && hasTo {
		if fromPort == 0 && toPort == 0 {
			return true
		}
		if targetPort >= fromPort && targetPort <= toPort {
			return true
		}
	}

	return false
}

func parsePolicyDocument(val interface{}) (map[string]interface{}, error) {
	switch v := val.(type) {
	case string:
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(v), &doc); err != nil {
			return nil, err
		}
		return doc, nil
	case map[string]interface{}:
		return v, nil
	default:
		return nil, fmt.Errorf("unexpected policy type")
	}
}

func extractStrings(val interface{}) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}
