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

package logging

import (
	"os"

	"github.com/fatih/color"
	"github.com/rs/zerolog"
)

func consoleMessageFormatter(msg interface{}) string {
	if msg == nil {
		return ""
	}
	return color.New(color.BgBlue).Sprint(msg)
}

func newStderrWriter() (wf *writerFilter, err error) {
	cw := zerolog.NewConsoleWriter()
	cw.Out = os.Stderr
	cw.TimeFormat = timeFormat
	cw.FormatMessage = consoleMessageFormatter
	wf = newWriterFilter(cw)
	return
}
