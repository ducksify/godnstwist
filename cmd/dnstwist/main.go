package main

import (
	"fmt"
	"os"

	"github.com/ducksify/godnstwist/pkg/dnstwist"
	"github.com/spf13/cobra"
)

const (
	version = "20250130"
	author  = "©ducksify"
	email   = "fegger@ducksify.com"
)

var (
	options dnstwist.Options
	rootCmd = &cobra.Command{
		Use:     "dnstwist",
		Short:   "Domain name permutation engine for detecting typo squatting, phishing and corporate espionage",
		Long:    `dnstwist is a domain name permutation engine for detecting typo squatting, phishing and corporate espionage.`,
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if options.Domain == "" {
				return fmt.Errorf("domain is required")
			}

			// Create engine
			engine, err := dnstwist.New(options)
			if err != nil {
				return fmt.Errorf("error creating engine: %v", err)
			}

			// Get raw results
			results, err := engine.GetResults()
			if err != nil {
				return fmt.Errorf("error getting results: %v", err)
			}

			// Format and output results
			output := results.Format(options.Format)
			fmt.Print(output)
			return nil
		},
	}
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Add flags
	rootCmd.Flags().StringVarP(&options.Domain, "domain", "d", "", "Domain name to analyze")
	rootCmd.Flags().BoolVarP(&options.All, "all", "a", false, "Print all DNS records instead of the first ones")
	rootCmd.Flags().BoolVarP(&options.Banners, "banners", "b", false, "Determine HTTP and SMTP service banners")
	rootCmd.Flags().StringVarP(&options.Dictionary, "dictionary", "", "", "Generate more domains using dictionary file")
	rootCmd.Flags().StringVarP(&options.Format, "format", "f", "cli", "Output format (cli, csv, json, list)")
	rootCmd.Flags().StringVarP(&options.Fuzzers, "fuzzers", "", "", "Fuzzing algorithms to use (comma-separated)")
	rootCmd.Flags().BoolVarP(&options.GeoIP, "geoip", "g", false, "Perform GeoIP location lookup")
	rootCmd.Flags().StringVarP(&options.LSH, "lsh", "", "", "Evaluate web page similarity with LSH algorithm (ssdeep, tlsh)")
	rootCmd.Flags().StringVarP(&options.LSHURL, "lshurl", "", "", "Override URL to fetch the original web page from")
	rootCmd.Flags().BoolVarP(&options.MXCheck, "mxcheck", "m", false, "Check if MX host can be used to intercept emails")
	rootCmd.Flags().BoolVarP(&options.NSCheck, "nscheck", "x", false, "Check for nameserver records")
	rootCmd.Flags().StringVarP(&options.Output, "output", "o", "", "Save output to file")
	rootCmd.Flags().BoolVarP(&options.Registered, "registered", "r", false, "Show only registered domain names")
	rootCmd.Flags().BoolVarP(&options.Unregistered, "unregistered", "u", false, "Show only unregistered domain names")
	rootCmd.Flags().StringVarP(&options.RegisteredBy, "registered-by", "", "A", "Record type to determine registration (A or NS)")
	rootCmd.Flags().BoolVarP(&options.PHash, "phash", "p", false, "Render web pages and evaluate visual similarity")
	rootCmd.Flags().StringVarP(&options.PHashURL, "phashurl", "", "", "Override URL to render the original web page from")
	rootCmd.Flags().StringVarP(&options.Screenshots, "screenshots", "s", "", "Save web page screenshots into directory")
	rootCmd.Flags().IntVarP(&options.Threads, "threads", "t", 10, "Number of concurrent threads")
	rootCmd.Flags().BoolVarP(&options.Whois, "whois", "w", false, "Look up WHOIS database for creation date and registrar")
	rootCmd.Flags().StringSliceVarP(&options.TLD, "tld", "", []string{}, "Swap TLD for the original domain from files (can be specified multiple times)")
	rootCmd.Flags().StringVarP(&options.Nameservers, "nameservers", "n", "", "DNS or DoH servers to query (comma-separated)")
	rootCmd.Flags().StringVarP(&options.UserAgent, "useragent", "", "Mozilla/5.0 dnstwist", "User-Agent string")

	// Mark required flags
	rootCmd.MarkFlagRequired("domain")
}
