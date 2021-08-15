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
	"io"
	"time"

	"github.com/rs/zerolog"
)

const (
	InitStderrLevel = "warn"
	timeFormat      = time.StampMilli
)

type Logger struct {
	zerolog.Logger
}

type Instance struct {
	Logger
	Stdout      *writerFilter
	Stderr      *writerFilter
	Syslog      *writerFilter
	multiWriter zerolog.LevelWriter
}

var Main Instance

var timestampHook = zerolog.HookFunc(func(e *zerolog.Event, _ zerolog.Level, _ string) {
	e.Timestamp()
})

func init() {
	zerolog.TimeFieldFormat = timeFormat
	i, err := NewInstance()
	if err != nil {
		defer Main.Err(err).Msg("Unable to setup main logger")
	}
	// This level is used only for errors during initialization and is later
	// reset by the program during argument/config parsing.
	i.Stderr.SetLevel(InitStderrLevel)
	Main = i
}

func BaseLogger(i io.Writer) Logger {
	return Logger{zerolog.New(i).Hook(timestampHook)}
}

func CtxLogger(ctx zerolog.Context) Logger {
	return Logger{ctx.Logger()}
}

func NewInstance() (i Instance, err error) {
	if err == nil {
		i.Stderr, err = newConsoleWriter()
	}
	if err == nil {
		i.Syslog, err = newSyslogWriter()
	}
	i.multiWriter = zerolog.MultiLevelWriter(i.Stderr, i.Syslog)
	i.Logger = BaseLogger(i.multiWriter)
	return
}
