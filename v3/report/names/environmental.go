package names

import "golang.org/x/text/language"

var environmentalMap = langNameMap{
	language.English:  "Environmental Metrics",
	language.Japanese: "環境評価基準",
}

//EnvironmentalMetrics returns string instance name for display
func EnvironmentalMetrics(lang language.Tag) string {
	return environmentalMap.getNameInLang(lang)
}

//EnvironmentalMetricsValueOf returns string instance name for display
func EnvironmentalMetricsValueOf(lang language.Tag) string {
	return metricVakueMap.getNameInLang(lang)
}

/* Copyright 2022 Spiegel
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
