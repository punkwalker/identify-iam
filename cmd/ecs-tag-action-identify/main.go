package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/punkwalker/identify-iam/pkg/analysis"
	"gopkg.in/yaml.v2"
)

func main() {

	opts := analysis.Options.NewOpts(analysis.Options{})

	cfg, err := analysis.Configuration.NewConfig(analysis.Configuration{})

	if err != nil {
		panic(err)
	}

	wg := analysis.Configuration.NewWaitGroup(analysis.Configuration{})

	for _, a := range analysis.AnalysisList {
		wg.Add(1)
		go func(cfg *analysis.Configuration, opts *analysis.Options) {
			defer wg.Done()
			a.Identify(cfg, opts)
		}(cfg, opts)
		wg.Wait()
	}

	if opts.Output != "json" {
		identifiedYAML, err := yaml.Marshal(cfg.Identified)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v", string(identifiedYAML))

	} else {
		identifiedJSON, err := json.Marshal(cfg.Identified)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%v", string(identifiedJSON))
	}

}
