package analysis

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() {
	RegisterAnalysis(&ROLE{})
}

type ROLE struct {
}

func (r *ROLE) Identify(client *iam.Client, identified *IdentifiedEntities) {

	rolePaginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{}, func(po *iam.ListRolesPaginatorOptions) {
		po.Limit = 100
	})

	for rolePaginator.HasMorePages() {

		output, err := rolePaginator.NextPage(context.TODO())

		if err != nil {
			panic(err)
		}

		for start := 0; start < len(output.Roles); start += BatchSize {
			end := start + BatchSize

			if end > len(output.Roles) {
				end = len(output.Roles)
			}

			roleNames := output.Roles[start:end]

			wg.Add(1)
			go func(roleNames *[]types.Role) {
				defer wg.Done()
				r.ProcessBatch(roleNames, client, identified)
			}(&roleNames)

		}
		wg.Wait()
	}
}

func (r *ROLE) ProcessBatch(roles *[]types.Role, client *iam.Client, identified *IdentifiedEntities) {
	managedPolicies := []IAMPolicy{}

	for _, role := range *roles {
		rl := IAMRole{
			Name: *role.RoleName,
		}
		r.ListPolicies(role.RoleName, client, &rl, &managedPolicies)
		if rl.InlinePolicies != nil {
			mu.Lock()
			identified.Roles = append(identified.Roles, rl)
			mu.Unlock()
		}
	}

	if managedPolicies != nil {
		mu.Lock()
		identified.ManagedPolicies = append(identified.ManagedPolicies, managedPolicies...)
		mu.Unlock()
	}
}

func (r *ROLE) ListPolicies(roleName *string, client *iam.Client, role *IAMRole, managedPolicies *[]IAMPolicy) {

	inlinePolicies, err := client.ListRolePolicies(context.TODO(), &iam.ListRolePoliciesInput{RoleName: roleName})

	if err != nil {
		panic(err)
	}

	attachedPolicies, err := client.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{RoleName: roleName})

	if err != nil {
		panic(err)
	}

	if inlinePolicies != nil {
		for _, policyName := range inlinePolicies.PolicyNames {
			r.VerifyInlinePolicy(&policyName, roleName, client, role)
		}
	}

	if attachedPolicies != nil {
		for _, policy := range attachedPolicies.AttachedPolicies {
			VerifyAttachedPolicy(policy.PolicyArn, client, managedPolicies)
		}
	}
}

func (r *ROLE) VerifyInlinePolicy(policyName *string, roleName *string, client *iam.Client, role *IAMRole) bool {

	policy := IAMPolicy{
		PolicyName: *policyName,
	}

	output, err := client.GetRolePolicy(context.TODO(), &iam.GetRolePolicyInput{PolicyName: policyName, RoleName: roleName})

	if err != nil {
		panic(err)
	}

	p := parseDocument(output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}

	for _, statement := range p.Statements.Values() {
		actions := statement.Action.Values()
		effect := statement.Effect

		if isECSAction(strings.Join(actions, ",")) && effect == "Allow" {
			policy.StatementIds = append(policy.StatementIds, statement.Sid)
		}
	}

	if policy.StatementIds != nil {
		role.InlinePolicies = append(role.InlinePolicies, policy)
		return true
	}

	return false
}

// func (r *ROLE) VerifyAttachedPolicy(policyArn *string, client *iam.Client, entity *IdentifiedEntity) {

// 	if isAWSManaged(policyArn) {
// 		return
// 	}

// 	policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{PolicyArn: policyArn})

// 	AttachedPolicy := IAMPolicy{
// 		PolicyName: *policy.Policy.PolicyName,
// 	}

// 	if err != nil {
// 		panic(err)
// 	}

// 	policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{PolicyArn: policyArn, VersionId: policy.Policy.DefaultVersionId})

// 	if err != nil {
// 		panic(err)
// 	}

// 	p := parseDocument(policyVersion.PolicyVersion.Document)

// 	for _, statement := range p.Statements.Values() {
// 		actions := statement.Action.Values()
// 		effect := statement.Effect
// 		if isECSAction(strings.Join(actions, ",")) && effect == "Allow" {
// 			AttachedPolicy.StatementIds = append(AttachedPolicy.StatementIds, statement.Sid)
// 		}
// 	}

// 	if AttachedPolicy.StatementIds != nil {
// 		entity.Policies = append(entity.Policies, AttachedPolicy)
// 	}
// }
