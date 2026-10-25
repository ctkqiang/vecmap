package test

import (
	"testing"

	"vecmap/internal/utilities"
)

func TestParseVersion(t *testing.T) {
	version := utilities.ParseVersion("v1.9.0-dev")
	if !version.Valid {
		t.Fatalf("expected valid version, got invalid")
	}
	if version.Major != 1 || version.Minor != 9 || version.Patch != 0 || version.Pre != "dev" {
		t.Fatalf("unexpected parse result: %+v", version)
	}
	if utilities.ParseVersion("nonsense").Valid {
		t.Fatalf("expected invalid version for nonsense")
	}
	if utilities.ParseVersion("1.9").Valid {
		if v := utilities.ParseVersion("1.9"); v.Minor != 9 || v.Patch != 0 {
			t.Fatalf("expected 1.9 to normalize to patch 0: %+v", v)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.9.0", "1.8.2", 1},
		{"1.8.2", "1.9.0", -1},
		{"2.5.21", "2.5.21", 0},
		{"1.9.0", "1.9.0-dev", 1},
		{"1.9.0-rc1", "1.9.0", -1},
	}
	for _, testCase := range cases {
		got := utilities.CompareVersions(testCase.left, testCase.right)
		if got != testCase.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", testCase.left, testCase.right, got, testCase.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	cases := []struct {
		version string
		ranges  []string
		want    bool
	}{
		{"1.8.2", []string{"< 1.9.0"}, true},
		{"1.9.0", []string{"< 1.9.0"}, false},
		{"1.15.5", []string{">= 1.9.3, < 1.16.0"}, true},
		{"1.16.0", []string{">= 1.9.3, < 1.16.0"}, false},
		{"2.5.10", []string{"< 2.4.24", ">= 2.5.0, < 2.5.21"}, true},
		{"2.5.21", []string{"< 2.4.24", ">= 2.5.0, < 2.5.21"}, false},
		{"2.6.22", []string{"<= 2.6.22", "== 3.0.0"}, true},
		{"3.0.0", []string{"<= 2.6.22", "== 3.0.0"}, true},
		{"2.6.23", []string{"<= 2.6.22", "== 3.0.0"}, false},
		{"30.1", []string{"< 29.1", ">= 30.0, < 30.2"}, true},
		{"29.1", []string{"< 29.1", ">= 30.0, < 30.2"}, false},
		{"1.5.9", []string{">= 1.0.0, <= 1.5.9"}, true},
		{"1.6.0", []string{">= 1.0.0, <= 1.5.9"}, false},
		{"2.14.1", []string{">= 2.0-beta9, <= 2.15.0"}, true},
		{"2.17.1", []string{">= 2.0-beta9, <= 2.15.0"}, false},
		{"1.37.7", []string{"<= 1.37.7"}, true},
		{"1.38.0-rc.0", []string{"<= 1.37.7"}, false},
	}
	for _, testCase := range cases {
		got, _ := utilities.VersionInRange(testCase.version, testCase.ranges)
		if got != testCase.want {
			t.Fatalf("VersionInRange(%q, %v) = %v, want %v", testCase.version, testCase.ranges, got, testCase.want)
		}
	}
}

func TestVersionInRangeInvalid(t *testing.T) {
	if got, _ := utilities.VersionInRange("garbage", []string{"< 1.9.0"}); got {
		t.Fatalf("expected invalid version to not match")
	}
	if got, _ := utilities.VersionInRange("1.8.2", nil); got {
		t.Fatalf("expected empty ranges to not match")
	}
}
