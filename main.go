package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/bvisness/spall-go"
	"github.com/spf13/cobra"
)

var reFrame = regexp.MustCompile(`^frame\s*\d+\s*(\d+)\s*(\d+)$`)
var reCount = regexp.MustCompile(`^count\s*(\d+)$`)
var reOffset = regexp.MustCompile(`\+[^+]*$`)
var reCFunctionArgument = regexp.MustCompile(`(::.*)[(<].*`)

func main() {
	rootCmd := &cobra.Command{
		Use: "dtrace2spall",
		Run: func(cmd *cobra.Command, args []string) {
			var f io.Writer = os.Stdout
			if out, err := cmd.PersistentFlags().GetString("out"); err == nil && out != "" {
				if out == "-" {
					f = os.Stdout
				} else {
					f, err = os.Create(out)
					if err != nil {
						panic(err)
					}
				}

				passthrough, err := cmd.PersistentFlags().GetBool("passthrough")
				if err != nil {
					panic(err)
				}
				if passthrough && f == os.Stdout {
					fmt.Fprintln(os.Stderr, "ERROR: --passthrough requires the use of --out (because --passthrough needs stdout)")
					os.Exit(1)
				}

				freq, err := cmd.PersistentFlags().GetInt("freq")
				if err != nil {
					panic(err)
				}

				p := spall.NewProfile(f, 1_000_000/spall.TimestampUnit(freq)) // (µs/s) / (samples/s) = µs/sample
				defer p.Close()
				e := p.NewEventer()
				defer e.Close()

				var pid, tid uint32
				var currentStack []string // the previous entry's stack
				var stackEntries []string // the stack entries we've built up so far (reverse order because hooray dtrace)
				var now float64 = 0

				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if passthrough {
						fmt.Fprintln(os.Stdout, line)
					}

					line = strings.TrimSpace(line)
					if line == "" {
						// norp
					} else if m := reFrame.FindStringSubmatch(line); m != nil {
						// Start a new frame
						pidStr := m[1]
						tidStr := m[2]
						pidU64, err := strconv.ParseUint(pidStr, 10, 32)
						if err != nil {
							panic(err)
						}
						tidU64, err := strconv.ParseUint(tidStr, 10, 32)
						if err != nil {
							panic(err)
						}
						pid = uint32(pidU64)
						tid = uint32(tidU64)
						stackEntries = stackEntries[:0] // reset stack in place (reuse memory)
					} else if m := reCount.FindStringSubmatch(line); m != nil {
						// End of a stack; track the stuff
						countStr := m[1]

						count, err := strconv.Atoi(countStr)
						if err != nil {
							panic(fmt.Errorf("'%s' is not a valid sample count", countStr))
						}
						now += float64(count)

						for i := 0; i < len(stackEntries); i++ {
							entry := stackEntries[len(stackEntries)-1-i] // accessing in reverse
							if i < len(currentStack) && currentStack[i] != entry {
								// Different entry - end everything past this point
								for j := len(currentStack) - 1; j >= i; j-- {
									e.EndTidPid(tid, pid, now)
								}
								currentStack = currentStack[:i]
							}
							if i >= len(currentStack) {
								// New stack entries; begin these events
								e.BeginTidPid(entry, uint32(tid), pid, now)
								currentStack = append(currentStack, entry)
							}
						}
					} else {
						// One entry in a stack
						line = reOffset.ReplaceAllString(line, "")
						line = reCFunctionArgument.ReplaceAllString(line, "$1")
						if line == "" {
							line = "-"
						}
						stackEntries = append(stackEntries, line)
					}
				}
				if err := scanner.Err(); err != nil {
					fmt.Fprintln(os.Stderr, "reading standard input:", err)
				}

				// Pop the remaining items
				for i := len(currentStack) - 1; i >= 0; i-- {
					e.EndTidPid(tid, pid, now)
				}
			}
		},
	}
	rootCmd.PersistentFlags().IntP("freq", "f", 1000, "The frequency of profile sampling, in Hz.")
	rootCmd.PersistentFlags().StringP("out", "o", "", "The file to write the results to. Use \"-\" for stdout.")
	rootCmd.PersistentFlags().Bool("combine", false, "Combine identical stacks to make traces less noisy. (Doing so loses information about ordering.)")
	rootCmd.PersistentFlags().Bool("passthrough", false, "Pass the input data through to stdout, making this tool invisible to pipelines. Requires --out.")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
