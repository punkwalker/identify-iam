package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/punkwalker/identify-iam/pkg/analysis"
	"gopkg.in/yaml.v2"
)

func main() {
	format := flag.String("o", "yaml", "Output format")
	flag.Parse()

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	client := iam.NewFromConfig(cfg)

	analysis.BatchSize = 10

	var identified analysis.IdentifiedEntities

	for _, a := range analysis.AnalysisList {
		a.Identify(client, &identified)
	}

	if *format != "json" {
		identifiedYAML, err := yaml.Marshal(identified)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v", string(identifiedYAML))

	} else {
		identifiedJSON, err := json.Marshal(identified)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v", string(identifiedJSON))
	}

}
