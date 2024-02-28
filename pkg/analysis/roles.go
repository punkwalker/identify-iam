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

func (r *ROLE) Identify(cfg *Configuration, opts *Options) {

	wg := Configuration.NewWaitGroup(Configuration{})

	rolePaginator := iam.NewListRolesPaginator(cfg.IAMClient, &iam.ListRolesInput{}, func(po *iam.ListRolesPaginatorOptions) {
		po.Limit = cfg.PageSize
	})

	go QueueWorker(cfg, opts)

	for rolePaginator.HasMorePages() {

		output, err := rolePaginator.NextPage(context.TODO())

		if err != nil {
			panic(err)
		}

		batchSize := len(output.Roles)

		if len(output.Roles) > opts.Concurrancy {
			batchSize = (len(output.Roles) / opts.Concurrancy)
		}
		for start := 0; start < len(output.Roles); start += batchSize {

			end := start + batchSize

			if end == 0 {
				break
			}
			if end > len(output.Roles) {
				end = len(output.Roles)
			}

			roleNames := output.Roles[start:end]

			wg.Add(1)
			go func(roleNames *[]types.Role) {
				defer wg.Done()
				r.ListPolicies(roleNames, cfg)
			}(&roleNames)

		}
		wg.Wait()
	}
}

func (r *ROLE) ListPolicies(roles *[]types.Role, cfg *Configuration) {

	for _, role := range *roles {
		mu := Configuration.NewMutex(Configuration{})
		entity := Entity{
			Name:     *role.RoleName,
			Type:     "Role",
			Policies: []string{},
		}

		idEntity := IdentifiedEntity{
			Name:             entity.Name,
			DeniedByPolicies: []string{},
		}

		inlinePolicies, err := cfg.IAMClient.ListRolePolicies(context.TODO(), &iam.ListRolePoliciesInput{RoleName: &entity.Name})

		if err != nil {
			panic(err)
		}

		if inlinePolicies != nil {
			for _, policyName := range inlinePolicies.PolicyNames {
				r.VerifyInlinePolicy(&policyName, &entity, cfg.IAMClient)
			}
		}

		attachedPolicies, err := cfg.IAMClient.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{RoleName: &entity.Name})

		if err != nil {
			panic(err)
		}

		if attachedPolicies != nil {
			for _, policy := range attachedPolicies.AttachedPolicies {
				mu.Lock()
				inCache := cfg.PolicyDecisionCache[*policy.PolicyArn]
				mu.Unlock()

				if inCache != "" {

					if inCache == "Denied" {

						idEntity.Decision = types.PolicyEvaluationDecisionTypeExplicitDeny
						idEntity.DeniedByPolicies = append(idEntity.DeniedByPolicies, *policy.PolicyArn)
						addEntity(&entity, idEntity, cfg)
					}

				} else {
					VerifyAttachedPolicy(policy.PolicyArn, &entity, cfg.IAMClient)
				}
			}
		}

		if len(entity.Policies) != 0 {
			cfg.Queue <- entity
		}
	}
}

func (r *ROLE) VerifyInlinePolicy(policyName *string, entity *Entity, client *iam.Client) {

	output, err := client.GetRolePolicy(context.TODO(), &iam.GetRolePolicyInput{PolicyName: policyName, RoleName: &entity.Name})

	if err != nil {
		panic(err)
	}

	policyDocument, err := url.QueryUnescape(*output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	processPolicy(&policyDocument, &entity.Policies, policyName)

}
