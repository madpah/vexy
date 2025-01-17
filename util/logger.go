/**
 * Copyright (c) 2023-present Paul Horton. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package util

import (
	"bytes"
	"fmt"
	"runtime"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

type LogFormatter struct {
	Module string
}

func (f *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	// Skip 2, 0: callers(), 1: GetCaller, 2: LogFormatter()
	fn := getCaller(3, []string{"logrus"})

	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	b := &bytes.Buffer{}

	fmt.Fprintf(b, "%-23s", entry.Time.Format("2006-01-02T15:04:05.999"))
	fmt.Fprintf(b, "|%s|%s|%s:",
		strings.ToUpper(entry.Level.String())[0:4], f.Module, fn)
	if len(entry.Message) > 0 {
		fmt.Fprintf(b, " %s", entry.Message)
	}
	if len(keys) > 0 {
		fmt.Fprintf(b, " - ")
		for i, key := range keys {
			b.WriteString(key)
			b.WriteByte('=')
			fmt.Fprintf(b, "%+v", entry.Data[key])
			if i < len(keys)-1 {
				b.WriteByte(' ')
			}
		}
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

func getCaller(skip int, excludes []string) string {
	var fn string

	pc := make([]uintptr, 20)
	n := runtime.Callers(skip, pc)
	frames := runtime.CallersFrames(pc)
OUTER:
	for i := 0; i < n; i++ {
		frame, more := frames.Next()
		// fmt.Printf("********  %s\n", frame.Function)
		if !more {
			break
		}
		fpath := frame.Function
		for _, exclude := range excludes {
			if strings.Contains(fpath, exclude) {
				continue OUTER
			}
		}
		slash := strings.LastIndex(fpath, "/")
		if slash == -1 {
			fn = fpath
		} else {
			fn = fpath[slash+1:]
		}
		return fn
	}

	return fn
}
