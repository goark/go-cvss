package base

import "golang.org/x/text/language"

var (
	avNameMap = map[language.Tag]string{
		language.English:  "Attack Vector",
		language.Japanese: "攻撃元区分",
	}
	avValueNameUnknownMap = map[language.Tag]string{
		language.English:  "Unknown",
		language.Japanese: "不明",
	}
	avValueNamePhysicalMap = map[language.Tag]string{
		language.English:  "Physical",
		language.Japanese: "物理",
	}
	avValueNameLocalMap = map[language.Tag]string{
		language.English:  "Local",
		language.Japanese: "ローカル",
	}
	avValueNameAdjacentMap = map[language.Tag]string{
		language.English:  "Adjacent",
		language.Japanese: "隣接",
	}
	avValueNameNetworkMap = map[language.Tag]string{
		language.English:  "Network",
		language.Japanese: "ネットワーク",
	}
)

//Name returns string instance name for display
func (av AttackVector) Name(lang language.Tag) string {
	if s, ok := avNameMap[lang]; ok {
		return s
	}
	return avNameMap[language.English]
}

//Name returns string name of value for display
func (av AttackVector) NameOfValue(lang language.Tag) string {
	var mp map[language.Tag]string
	switch av {
	case AttackVectorPhysical:
		mp = avValueNamePhysicalMap
	case AttackVectorLocal:
		mp = avValueNameLocalMap
	case AttackVectorAdjacent:
		mp = avValueNameAdjacentMap
	case AttackVectorNetwork:
		mp = avValueNameNetworkMap
	default:
		mp = avValueNameUnknownMap
	}
	if s, ok := mp[lang]; ok {
		return s
	}
	return mp[language.English]
}

/* Copyright 2018 Spiegel
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
