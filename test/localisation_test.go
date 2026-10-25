package test

import (
	"testing"

	"vecmap/internal/utilities"
)

// TestLocalisation 覆盖语言识别、语言切换、取词与两份词典的键集一致性。
func TestLocalisation(t *testing.T) {
	if got := utilities.LanguageFromCode("zh_CN.UTF-8"); got != utilities.Chinese {
		t.Fatalf("zh_CN.UTF-8 -> %q, want zh", got)
	}
	if got := utilities.LanguageFromCode("zh-Hans-CN"); got != utilities.Chinese {
		t.Fatalf("zh-Hans-CN -> %q, want zh", got)
	}
	if got := utilities.LanguageFromCode("en_US.UTF-8"); got != utilities.English {
		t.Fatalf("en_US.UTF-8 -> %q, want en", got)
	}
	if got := utilities.LanguageFromCode("ja_JP.UTF-8"); got != "" {
		t.Fatalf("ja_JP -> %q, want empty", got)
	}

	if got := utilities.SetLocaleByCode("zh_TW"); got != utilities.Chinese {
		t.Fatalf("SetLocaleByCode(zh_TW) -> %q", got)
	}
	if got := utilities.SetLocaleByCode("fr_FR"); got != utilities.English {
		t.Fatalf("unknown code must fall back to en, got %q", got)
	}

	utilities.SetLocale(utilities.Chinese)
	if got := utilities.T(utilities.KeySessionCreated); got == utilities.KeySessionCreated || got == "" {
		t.Fatalf("zh translation missing: %q", got)
	}
	if got := utilities.Tf(utilities.KeySummaryTargets, 7); got != "目标数：7" {
		t.Fatalf("Tf zh = %q", got)
	}

	utilities.SetLocale(utilities.English)
	if got := utilities.Tf(utilities.KeySummaryTargets, 7); got != "targets: 7" {
		t.Fatalf("Tf en = %q", got)
	}
	if got := utilities.T("does.not.exist"); got != "does.not.exist" {
		t.Fatalf("missing key must echo itself, got %q", got)
	}

	// 两份词典必须键集一致，缺一个都会在这里报错
	enKeys := utilities.Keys(utilities.English)
	zhKeys := utilities.Keys(utilities.Chinese)
	if len(enKeys) == 0 {
		t.Fatal("英文词典为空")
	}
	if len(enKeys) != len(zhKeys) {
		t.Fatalf("词典键数不一致: en=%d zh=%d", len(enKeys), len(zhKeys))
	}
	zhSet := make(map[string]struct{}, len(zhKeys))
	for _, k := range zhKeys {
		zhSet[k] = struct{}{}
	}
	for _, k := range enKeys {
		if _, ok := zhSet[k]; !ok {
			t.Errorf("key %q missing in zh", k)
		}
	}

	// 词典必须覆盖所有已定义的键常量，防止新增常量却忘了翻译
	for _, k := range []string{
		utilities.KeyAppTitle,
		utilities.KeyDBReady,
		utilities.KeyLogPrefixInfo,
		utilities.KeySessionCreated,
		utilities.KeyStepScanPort,
		utilities.KeyVulnFound,
		utilities.KeySummaryHeader,
		utilities.KeyErrOperation,
	} {
		if got := utilities.T(k); got == k {
			t.Errorf("key constant %q not in dictionary", k)
		}
	}
}
