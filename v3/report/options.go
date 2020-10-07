package report

import "golang.org/x/text/language"

type options struct {
	lang language.Tag
}

//ReportOptionsFunc type is self-referential function type for report.newOptions() function. (functional options pattern)
type ReportOptionsFunc func(*options)

func newOptions(os ...ReportOptionsFunc) *options {
	opts := &options{lang: language.English}
	for _, o := range os {
		o(opts)
	}
	return opts
}

//WithOptionsLanguage function returns ReportOptionsFunc function value.
//This function is used in Server.CreateClient method that represents http.Client.
func WithOptionsLanguage(lang language.Tag) ReportOptionsFunc {
	return func(opts *options) {
		opts.lang = lang
	}
}

/* Copyright 2020 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
