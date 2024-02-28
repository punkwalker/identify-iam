package analysis

import (
	"flag"
	"fmt"
	"os"
	"regexp"
)

type Options struct {
	APIregex    *regexp.Regexp
	NewAction   []string
	Concurrancy int
	Output      string
}

func (o Options) NewOpts() *Options {
	apiListRegex := flag.String("api-regex", `(ecs:(Create(CapacityProvider|Cluster|Service|TaskSet)|Register(ContainerInstance|TaskDefinition)|(Run|Start)Task))|(ecs:(Create\*|Register\*|Run\*|Start*))`, "API Regexp to match related actions")
	newAction := flag.String("new-api", "ecs:TagResource", "New API Action to identify")
	concurrancy := flag.Int("concurrancy", 10, "Number of Concurrent Batches")
	format := flag.String("o", "yaml", "Output format. yaml or json")
	help := flag.Bool("help", false, "Print Usage")
	flag.Parse()

	if *help {
		usage()
	}

	defaultOpts := Options{
		APIregex:    regexp.MustCompile(*apiListRegex),
		NewAction:   []string{*newAction},
		Concurrancy: *concurrancy,
		Output:      *format,
	}

	return &defaultOpts
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}
