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

var reWhitespace = regexp.MustCompile(`\s+`)
var reCount = regexp.MustCompile(`^\d+$`)
var reOffset = regexp.MustCompile(`\+[^+]*$`)
var reCFunctionArgument = regexp.MustCompile(`(::.*)[(<].*`)

type State int

const (
	StateExpectingNewFrame State = iota + 1 // waiting for fields or the first entry in a stack
	StateInFrame                            // waiting for the count to end the frame
)

func main() {
	rootCmd := &cobra.Command{
		Use: "dtrace2spall",
		Run: func(cmd *cobra.Command, args []string) {
			var f io.Writer = os.Stdout
			if out, _ := cmd.PersistentFlags().GetString("out"); out != "" {
				if out == "-" {
					f = os.Stdout
				} else {
					var err error
					f, err = os.Create(out)
					if err != nil {
						panic(err)
					}
				}

				passthrough, _ := cmd.PersistentFlags().GetBool("passthrough")
				if passthrough && f == os.Stdout {
					fmt.Fprintln(os.Stderr, "ERROR: --passthrough requires the use of --out (because --passthrough needs stdout)")
					os.Exit(1)
				}

				freq, _ := cmd.PersistentFlags().GetInt("freq")
				fields, _ := cmd.PersistentFlags().GetStringSlice("fields")

				p := spall.NewProfile(f, 1_000_000/spall.TimestampUnit(freq)) // (µs/s) / (samples/s) = µs/sample
				defer p.Close()
				e := p.NewEventer()
				defer e.Close()

				state := StateExpectingNewFrame
				var pid, tid uint32
				var currentStack []string // the previous entry's stack
				var stackEntries []string // the stack entries we've built up so far (reverse order because hooray dtrace)
				var now float64 = 0

				addStackEntry := func(line string) {
					line = reOffset.ReplaceAllString(line, "")
					line = reCFunctionArgument.ReplaceAllString(line, "$1")
					if line == "" {
						line = "-"
					}
					stackEntries = append(stackEntries, line)
				}

				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if passthrough {
						fmt.Fprintln(os.Stdout, line)
					}

					line = strings.TrimSpace(line)
					if line == "" {
						// Nothin'. Must be between frames.
						state = StateExpectingNewFrame
					} else if state == StateExpectingNewFrame {
						// Non-empty line starts a new frame

						// Parse fields, or just start directly at the trace
						if len(fields) == 0 {
							addStackEntry(line)
						} else {
							fieldStrs := reWhitespace.Split(line, -1)
							if len(fieldStrs) != len(fields) {
								fmt.Fprintf(os.Stderr, "ERROR: Expected %d fields but got %d. Problematic line:\n", len(fields), len(fieldStrs))
								fmt.Fprintln(os.Stderr, line)
								os.Exit(1)
							}

							for i, fieldStr := range fieldStrs {
								switch fields[i] {
								case "pid":
									pidU64, err := strconv.ParseUint(fieldStr, 10, 32)
									if err != nil {
										fmt.Fprintf(os.Stderr, "ERROR: \"%s\" is not a valid pid.\n", fieldStr)
										os.Exit(1)
									}
									pid = uint32(pidU64)
								case "tid":
									tidU64, err := strconv.ParseUint(fieldStr, 10, 32)
									if err != nil {
										fmt.Fprintf(os.Stderr, "ERROR: \"%s\" is not a valid tid.\n", fieldStr)
										os.Exit(1)
									}
									tid = uint32(tidU64)
								default:
									// Ignore all others.
								}
							}
						}

						state = StateInFrame
					} else if state == StateInFrame && reCount.MatchString(line) {
						// End of a stack; track the stuff
						count, err := strconv.Atoi(line)
						if err != nil {
							panic(fmt.Errorf("'%s' is not a valid sample count", line))
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

						// Reset frame
						pid, tid = 0, 0
						stackEntries = stackEntries[:0] // reset stack in place (reuse memory)
						state = StateExpectingNewFrame
					} else if state == StateInFrame {
						// One entry in a stack
						addStackEntry(line)
					} else {
						panic("bad state!")
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
	rootCmd.PersistentFlags().StringSlice("fields", nil, "An array of fields preceding each stack. Valid fields: pid, tid. Any unrecognized fields will be ignored (consider using \"-\" for any such fields).")
	rootCmd.PersistentFlags().Bool("passthrough", false, "Pass the input data through to stdout, making this tool invisible to pipelines. Requires --out.")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
