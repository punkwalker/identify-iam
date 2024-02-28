package analysis

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() {
	RegisterAnalysis(&USER{})
}

type USER struct {
}

func (u *USER) Identify(cfg *Configuration, opts *Options) {

	wg := Configuration.NewWaitGroup(Configuration{})

	userPaginator := iam.NewListUsersPaginator(cfg.IAMClient, &iam.ListUsersInput{}, func(po *iam.ListUsersPaginatorOptions) {
		po.Limit = cfg.PageSize
	})

	go QueueWorker(cfg, opts)

	for userPaginator.HasMorePages() {

		output, err := userPaginator.NextPage(context.TODO())

		if err != nil {
			panic(err)
		}

		batchSize := len(output.Users)

		if len(output.Users) > opts.Concurrancy {
			batchSize = (len(output.Users) / opts.Concurrancy)
		}

		for start := 0; start < len(output.Users); start += batchSize {
			end := start + batchSize

			if end > len(output.Users) {
				end = len(output.Users)
			}

			userNames := output.Users[start:end]

			wg.Add(1)
			go func(userNames *[]types.User) {
				defer wg.Done()
				u.ListPolicies(userNames, cfg)
			}(&userNames)

		}
		wg.Wait()
	}
}

func (u *USER) ListPolicies(users *[]types.User, cfg *Configuration) {
	for _, user := range *users {
		mu := Configuration.NewMutex(Configuration{})
		entity := Entity{
			Name:     *user.UserName,
			Type:     "User",
			Policies: []string{},
		}

		idEntity := IdentifiedEntity{
			Name:             entity.Name,
			DeniedByPolicies: []string{},
		}

		inlinePolicies, err := cfg.IAMClient.ListUserPolicies(context.TODO(), &iam.ListUserPoliciesInput{UserName: &entity.Name})

		if err != nil {
			panic(err)
		}

		if inlinePolicies != nil {
			for _, policyName := range inlinePolicies.PolicyNames {
				u.VerifyInlinePolicy(&policyName, &entity, cfg.IAMClient)
			}
		}

		attachedPolicies, err := cfg.IAMClient.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{UserName: &entity.Name})

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

func (u *USER) VerifyInlinePolicy(policyName *string, entity *Entity, client *iam.Client) {

	output, err := client.GetUserPolicy(context.TODO(), &iam.GetUserPolicyInput{PolicyName: policyName, UserName: &entity.Name})

	if err != nil {
		panic(err)
	}

	policyDocument, err := url.QueryUnescape(*output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	processPolicy(&policyDocument, &entity.Policies, policyName)

}
