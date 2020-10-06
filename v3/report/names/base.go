package names

import "golang.org/x/text/language"

var baseTitleMap = langNameMap{
	language.English:  "Base Metrics",
	language.Japanese: "基本評価基準",
}
var baseVakueMap = langNameMap{
	language.English:  "Metric Value",
	language.Japanese: "評価値",
}

//BaseMetrics returns string instance name for display
func BaseMetrics(lang language.Tag) string {
	return baseTitleMap.getNameInLang(lang)
}

//BaseMetricsValueOf returns string instance name for display
func BaseMetricsValueOf(lang language.Tag) string {
	return baseVakueMap.getNameInLang(lang)
}

/* Copyright 2018-2020 Spiegel
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
