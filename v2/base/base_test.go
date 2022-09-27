package base

import "testing"

func TestScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{
			name:   "CVE-2002-0392",
			vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C",
			want:   7.8,
		},
		{
			name:   "CVE-2003-0818",
			vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			want:   10.0,
		},
		{
			name:   "CVE-2003-0062",
			vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C",
			want:   6.2,
		},
		{
			name:   "test",
			vector: "AV:N/AC:H/Au:M/C:C/I:N/A:C/E:U/RL:ND/RC:ND",
			want:   6.2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Decode(tt.vector)

			if err != nil {
				t.Error(err)
			}

			if got := m.Score(); got != tt.want {
				t.Errorf("Metrics.Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name   string
		vector string
	}{

		{name: "CVE-2019-18322", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-0145", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-7842", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-6821", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2020-11898", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2018-7779", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-18283", vector: "AV:N/AC:L/Au:S/C:C/I:C/A:C"},

		{name: "CVE-2019-6812", vector: "AV:L/AC:M/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2020-6988", vector: "AV:A/AC:L/Au:N/C:N/I:P/A:P"},
		{name: "CVE-2019-12264", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2018-7762", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-11466", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2017-12741", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2020-10040", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-4703", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2017-11780", vector: "AV:N/AC:L/Au:N/C:C/I:N/A:N"},

		{name: "CVE-2019-18335", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2018-11451", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2014-0781", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},
		{name: "CVE-2018-7064", vector: "AV:A/AC:M/Au:S/C:P/I:P/A:P"},

		{name: "CVE-2018-11452", vector: "AV:L/AC:M/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2020-6990", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-0169", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2017-0280", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2020-7502", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-0224", vector: "AV:N/AC:L/Au:S/C:N/I:P/A:N"},

		{name: "CVE-2019-6807", vector: "AV:N/AC:L/Au:S/C:P/I:P/A:P"},
		{name: "CVE-2018-14795", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-10939", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2018-18065", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-16556", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2017-0147", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2016-0868", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:P/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-11457", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2018-7851", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-13946", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:C"},
		{name: "CVE-2014-3888", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},
		{name: "CVE-2015-6488", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2014-0754", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2011-4861", vector: "AV:A/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2018-0175", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-18331", vector: "AV:L/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-8461", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2018-0158", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2017-0275", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2019-10953", vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2018-0167", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2018-7244", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-12263", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2019-10920", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2017-6017", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2015-6492", vector: "AV:N/AC:L/Au:S/C:P/I:P/A:P"},

		{name: "CVE-2019-18330", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2012-1815", vector: "AV:L/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-10931", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2017-14462", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2011-3389", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2018-7758", vector: "AV:N/AC:L/Au:N/C:N/I:P/A:P"},

		{name: "CVE-2019-18323", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2020-10044", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2019-13940", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2017-2680", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2019-6816", vector: "AV:N/AC:L/Au:N/C:N/I:P/A:C"},

		{name: "CVE-2018-7852", vector: "AV:N/AC:H/Au:N/C:N/I:P/A:P/E:U/RL:OF/RC:C"},

		{name: "CVE-2018-0473", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:N"},
		{name: "CVE-2019-6572", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2012-6437", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2018-7759", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2019-6852", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C"},
		{name: "CVE-2015-5698", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:C/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-2250", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-0472", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2019-13103", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2017-0279", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-0143", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2018-16196", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-12260", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2012-6440", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-7856", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2018-7809", vector: "AV:A/AC:L/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2019-13942", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2019-18217", vector: "AV:N/AC:L/Au:S/C:N/I:N/A:P"},
		{name: "CVE-2013-2761", vector: "AV:N/AC:L/Au:S/C:P/I:P/A:P"},

		{name: "CVE-2019-6813", vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2014-0300", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-0176", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-0146", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-7845", vector: "AV:N/AC:M/Au:N/C:C/I:N/A:N"},

		{name: "CVE-2020-11897", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2019-18314", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2019-6574", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2012-1816", vector: "AV:N/AC:L/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2019-18284", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-5390", vector: "AV:N/AC:H/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2013-0169", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-18336", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2017-0273", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:P/E:U/RL:OF/RC:C"},

		{name: "CVE-2019-18302", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-12256", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2016-7113", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2014-0301", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2016-9159", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2017-0274", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2018-7242", vector: "AV:L/AC:H/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-5176", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-13816", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-4690", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2016-5645", vector: "AV:N/AC:L/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2017-14470", vector: "AV:N/AC:H/Au:N/C:P/I:P/A:C"},
		{name: "CVE-2013-4651", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-7848", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-11460", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-7833", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-19282", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2020-11914", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2017-0272", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2015-7937", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2017-12089", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-6436", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-18292", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:P/E:POC/RL:OF/RC:C"},

		{name: "CVE-2019-6850", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2019-6806", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-13810", vector: "AV:N/AC:M/Au:S/C:N/I:P/A:N"},
		{name: "CVE-2018-19615", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:P"},
		{name: "CVE-2017-6030", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2018-14797", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-13814", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2020-7575", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2019-11478", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-0929", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2020-6980", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:C/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-2251", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:U/RC:C"},

		{name: "CVE-2019-19301", vector: "AV:N/AC:M/Au:S/C:N/I:P/A:N"},
		{name: "CVE-2019-6577", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-18289", vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-16563", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2020-11909", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2016-6329", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2020-11911", vector: "AV:N/AC:M/Au:S/C:P/I:N/A:N"},

		{name: "CVE-2019-18306", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2020-11905", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2019-18298", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2016-7112", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2019-18297", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2019-6833", vector: "AV:N/AC:M/Au:S/C:N/I:N/A:P"},

		{name: "CVE-2019-6851", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-13926", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2017-14464", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:P/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-2249", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-7843", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2015-1049", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},
		{name: "CVE-2016-2200", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:C"},
		{name: "CVE-2014-0782", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},
		{name: "CVE-2012-1814", vector: "AV:A/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2018-4833", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-2252", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2017-16740", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-19281", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2018-7800", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-6435", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2019-18300", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:N"},
		{name: "CVE-2017-6026", vector: "AV:L/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2014-2349", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-15377", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:N/E:POC/RL:OF/RC:C"},

		{name: "CVE-2019-18304", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-13808", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},
		{name: "CVE-2019-6568", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2009-3739", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-10919", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-7804", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-18311", vector: "AV:N/AC:M/Au:S/C:P/I:P/A:P"},
		{name: "CVE-2016-8561", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2018-3657", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2020-7525", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-6438", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2019-6848", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2020-11901", vector: "AV:N/AC:H/Au:N/C:N/I:C/A:N"},
		{name: "CVE-2014-0317", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2016-8672", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2017-12088", vector: "AV:L/AC:L/Au:N/C:C/I:N/A:C"},

		{name: "CVE-2019-18334", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2016-4784", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2018-11458", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2018-4843", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-11463", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2018-19616", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2016-8673", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2017-6868", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2017-0267", vector: "AV:N/AC:L/Au:N/C:N/I:P/A:P"},
		{name: "CVE-2012-1818", vector: "AV:N/AC:L/Au:S/C:P/I:N/A:N"},
		{name: "CVE-2018-7781", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-6858", vector: "AV:N/AC:L/Au:S/C:P/I:P/A:C"},
		{name: "CVE-2013-3633", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2020-10042", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2017-0271", vector: "AV:A/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-13809", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2012-6442", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C"},

		{name: "CVE-2019-6828", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C"},
		{name: "CVE-2013-0659", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-13925", vector: "AV:N/AC:L/Au:S/C:N/I:N/A:C"},
		{name: "CVE-2014-8479", vector: "AV:L/AC:M/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2014-0755", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-18303", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-6832", vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-13813", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2018-7083", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2017-14467", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-7834", vector: "AV:N/AC:L/Au:N/C:P/I:C/A:C/E:POC/RL:OF/RC:C"},
		{name: "CVE-2015-8214", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2017-7902", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2019-18288", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-5391", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2018-0174", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-4842", vector: "AV:N/AC:L/Au:N/C:N/I:P/A:P"},
		{name: "CVE-2018-7245", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2018-13812", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2020-10043", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-18328", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2012-1817", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2020-11914", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-6856", vector: "AV:N/AC:M/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-5074", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2019-18301", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{name: "CVE-2018-10592", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},

		{name: "CVE-2019-18320", vector: "AV:A/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2018-14793", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-7853", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-12261", vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2016-7090", vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N/E:H/RL:OF/RC:C"},
		{name: "CVE-2014-0160", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:P/E:POC/RL:OF/RC:C"},
		{name: "CVE-2014-2908", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},

		{name: "CVE-2019-5909", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2018-7830", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P"},

		{name: "CVE-2018-0470", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:C"},

		{name: "CVE-2019-18290", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C"},

		{name: "CVE-2017-12093", vector: "AV:N/AC:H/Au:N/C:N/I:P/A:N/E:U/RL:OF/RC:C"},

		{name: "CVE-2020-10045", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
		{name: "CVE-2017-9312", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N/E:POC/RL:OF/RC:C"},

		{name: "CVE-2020-5608", vector: "AV:N/AC:L/Au:S/C:P/I:N/A:N"},

		{name: "CVE-2018-15373", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},

		{name: "CVE-2018-16557", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2020-11913", vector: "AV:A/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:OF/RC:C"},

		{name: "CVE-2018-7821", vector: "AV:A/AC:L/Au:N/C:P/I:P/A:P"},
		{name: "CVE-2019-12257", vector: "AV:A/AC:L/Au:N/C:P/I:N/A:N"},
		{name: "CVE-2018-14526", vector: "AV:L/AC:L/Au:N/C:P/I:P/A:P"},

		{name: "CVE-2018-7846", vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC/RL:TF/RC:C"},

		{name: "CVE-2020-7477", vector: "AV:N/AC:L/Au:S/C:N/I:N/A:P"},

		{name: "CVE-2019-13933", vector: "AV:N/AC:M/Au:N/C:P/I:P/A:C"},

		{name: "CVE-2018-4848", vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N"},

		{name: "CVE-2020-7592", vector: "AV:N/AC:L/Au:N/C:P/I:P/A:C"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.vector)

			if err != nil {
				t.Error(err)
			}
		})
	}
}
