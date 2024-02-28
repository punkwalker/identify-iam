package analysis

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() {
	RegisterAnalysis(&GROUP{})
}

type GROUP struct {
}

func (g *GROUP) Identify(cfg *Configuration, opts *Options) {

	wg := Configuration.NewWaitGroup(Configuration{})

	groupPaginator := iam.NewListGroupsPaginator(cfg.IAMClient, &iam.ListGroupsInput{}, func(po *iam.ListGroupsPaginatorOptions) {
		po.Limit = cfg.PageSize
	})

	go QueueWorker(cfg, opts)

	for groupPaginator.HasMorePages() {

		output, err := groupPaginator.NextPage(context.TODO())

		if err != nil {
			panic(err)
		}

		batchSize := len(output.Groups)

		if len(output.Groups) > opts.Concurrancy {
			batchSize = (len(output.Groups) / opts.Concurrancy)
		}

		for start := 0; start < len(output.Groups); start += batchSize {

			end := start + batchSize

			if end > len(output.Groups) {
				end = len(output.Groups)
			}

			groupNames := output.Groups[start:end]

			wg.Add(1)
			go func(groupNames *[]types.Group) {
				defer wg.Done()
				g.ListPolicies(groupNames, cfg)
			}(&groupNames)
		}
		wg.Wait()
	}
}

func (g *GROUP) ListPolicies(groups *[]types.Group, cfg *Configuration) {
	for _, group := range *groups {
		mu := Configuration.NewMutex(Configuration{})
		entity := Entity{
			Name:     *group.GroupName,
			Type:     "Group",
			Policies: []string{},
		}

		idEntity := IdentifiedEntity{
			Name:             entity.Name,
			DeniedByPolicies: []string{},
		}
		inlinePolicies, err := cfg.IAMClient.ListGroupPolicies(context.TODO(), &iam.ListGroupPoliciesInput{GroupName: &entity.Name})

		if err != nil {
			panic(err)
		}

		if inlinePolicies != nil {
			for _, policyName := range inlinePolicies.PolicyNames {
				g.VerifyInlinePolicy(&policyName, &entity, cfg.IAMClient)
			}
		}

		attachedPolicies, err := cfg.IAMClient.ListAttachedGroupPolicies(context.TODO(), &iam.ListAttachedGroupPoliciesInput{GroupName: &entity.Name})

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
			cfg.Queue <- entity // Queue Entity for processing
		}
	}
}

func (g *GROUP) VerifyInlinePolicy(policyName *string, entity *Entity, client *iam.Client) {

	output, err := client.GetGroupPolicy(context.TODO(), &iam.GetGroupPolicyInput{PolicyName: policyName, GroupName: &entity.Name})

	if err != nil {
		panic(err)
	}

	policyDocument, err := url.QueryUnescape(*output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	processPolicy(&policyDocument, &entity.Policies, policyName)
}
