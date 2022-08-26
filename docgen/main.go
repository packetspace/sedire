/*
Copyright © 2021 Mike Joseph <mike@mjoseph.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"

	"github.com/packetspace/sedire/cmd"
	"github.com/packetspace/sedire/lib/logging"

	"github.com/spf13/cobra"
)

type generatorParams struct {
	Cmds   []*cobra.Command
	Dir    string
	Logger logging.Logger
}

var docsGenerators = make([]func(generatorParams), 0)

func main() {
	if len(os.Args) < 2 {
		logging.Main.Fatal().Msg("Path for docs output required")
	} else if len(os.Args) > 2 {
		logging.Main.Fatal().Msg("Too many arguments supplied")
	}
	dir := os.Args[1]

	logging.Main.Stderr.SetLevel("info")
	l := logging.CtxLogger(logging.Main.With().Str("directory", dir))

	cmds := cmd.AllCommands()
	for _, c := range cmds {
		c.DisableAutoGenTag = true
	}

	gp := generatorParams{
		Cmds:   cmds,
		Dir:    dir,
		Logger: l,
	}
	for _, f := range docsGenerators {
		f(gp)
	}
}
