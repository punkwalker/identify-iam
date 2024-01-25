package analysis

import (
	"context"
	"net/url"

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

func (r *ROLE) VerifyInlinePolicy(policyName *string, roleName *string, client *iam.Client, role *IAMRole) {

	output, err := client.GetRolePolicy(context.TODO(), &iam.GetRolePolicyInput{PolicyName: policyName, RoleName: roleName})

	if err != nil {
		panic(err)
	}

	policyDocument, err := url.QueryUnescape(*output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	// Proceed Only if we see any of the associated API action
	if isAction(APIListRegex, &policyDocument) {

		policy := IAMPolicy{
			PolicyName: *policyName,
		}

		processPolicy(&policyDocument, &policy)

		if policy.StatementIds != nil {
			role.InlinePolicies = append(role.InlinePolicies, policy)
		}

	}
}
