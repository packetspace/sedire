// +build all docs,man

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

package cmd

import (
	"github.com/Mike-Joseph/sedire/lib/logging"

	"github.com/spf13/cobra/doc"
)

func init() {
	f := func(dir string, logger logging.Logger) {
		header := &doc.GenManHeader{
			Title:   "sedire",
			Section: "8",
		}
		err := doc.GenManTree(rootCmd, header, dir)
		logger.Err(err).Str("command", "root").Msg("Generate man tree")
	}
	docsGenerators = append(docsGenerators, f)
}
