package dkim

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

var headerTests = []struct {
	h header
	s string
}{
	{
		h: header{"From: <mistuha@kiminonawa.moe>\r\n"},
		s: "From: <mistuha@kiminonawa.moe>\r\n\r\n",
	},
	{
		h: header{
			"From: <mistuha@kiminonawa.moe>\r\n",
			"Subject: Your Name\r\n",
		},
		s: "From: <mistuha@kiminonawa.moe>\r\n" +
			"Subject: Your Name\r\n" +
			"\r\n",
	},
}

func TestReadHeader(t *testing.T) {
	for _, test := range headerTests {
		r := strings.NewReader(test.s)
		h, err := readHeader(bufio.NewReader(r))
		if err != nil {
			t.Fatalf("Expected no error while reading error, got: %v", err)
		}

		if !reflect.DeepEqual(h, test.h) {
			t.Errorf("Expected header to be \n%v\n but got \n%v", test.h, h)
		}
	}
}

func TestReadHeader_incomplete(t *testing.T) {
	r := strings.NewReader("From: <mistuha@kiminonawa.moe>\r\nTo")
	_, err := readHeader(bufio.NewReader(r))
	if err == nil {
		t.Error("Expected an error while reading incomplete header")
	}
}

func TestFormatHeaderParams(t *testing.T) {
	params := map[string]string{
		"v": "1",
		"a": "rsa-sha256",
		"d": "example.org",
	}

	expected := "a=rsa-sha256; d=example.org; v=1;"

	s := formatHeaderParams(params)
	if s != expected {
		t.Errorf("Expected formatted params to be %q, but got %q", expected, s)
	}
}

func TestParseHeaderParams_malformed(t *testing.T) {
	_, err := parseHeaderParams("abc; def")
	if err == nil {
		t.Error("Expected an error when parsing malformed header params")
	}
}

func TestHeaderPicker_Pick(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		predefinedHeaders := []string{"From", "to"}
		headers := header{
			"from: fst",
			"To: snd",
		}
		picker := newHeaderPicker(headers)
		for i, k := range predefinedHeaders {
			if headers[i] != picker.Pick(k) {
				t.Errorf("Parameter %s not found in headers %s", k, headers)
			}
		}
	})
	t.Run("a few same headers", func(t *testing.T) {
		predefinedHeaders := []string{"to", "to", "to"}
		// same headers must returns from Bottom to Top
		headers := header{
			"To: trd",
			"To: snd",
			"To: fst",
		}
		var lh = len(headers) - 1
		picker := newHeaderPicker(headers)
		for i, k := range predefinedHeaders {
			if headers[lh-i] != picker.Pick(k) {
				t.Errorf("Parameter %s not found in headers %s", k, headers)
			}
		}

	})
}

func TestHeaderPicker_DeclarationOrderBindsConcreteInstances(t *testing.T) {
	headers := header{
		"From: top\r\n",
		"Received: first\r\n",
		"Subject: s\r\n",
		"Received: second\r\n",
		"To: bottom\r\n",
	}
	keys := []string{"To", "Received", "Subject", "Received", "From", "Received"}
	want := []struct {
		index int
		name  string
		raw   string
	}{
		{4, "To", "To: bottom\r\n"},
		{3, "Received", "Received: second\r\n"},
		{2, "Subject", "Subject: s\r\n"},
		{1, "Received", "Received: first\r\n"},
		{0, "From", "From: top\r\n"},
	}

	picker := newHeaderPicker(headers)
	for i, key := range keys {
		instance, ok := picker.pick(key)
		if i == len(want) {
			if ok {
				t.Errorf("Expected the sixth Received to be missing, got %+v", instance)
			}
			continue
		}
		if !ok {
			t.Fatalf("Pick(%q) #%v did not find a header", key, i)
		}
		if instance.Index != want[i].index || instance.Name != want[i].name || instance.Raw != want[i].raw {
			t.Errorf("Pick(%q) #%v = %+v, want index=%v name=%q raw=%q",
				key, i, instance, want[i].index, want[i].name, want[i].raw)
		}
	}
}

func TestHeaderPicker_BindIsStableAcrossRetries(t *testing.T) {
	headers := header{
		"Received: first\r\n",
		"From: sender@example.org\r\n",
		"Received: second\r\n",
	}
	keys := []string{"Received", "From", "Received"}

	picker := newHeaderPicker(headers)
	first := picker.Bind(keys)
	second := picker.Bind(keys)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Expected stable bindings across retries, got\n%+v\nand\n%+v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("Expected three bound instances, got %+v", first)
	}
	if first[0].Raw != "Received: second\r\n" || first[2].Raw != "Received: first\r\n" {
		t.Errorf("Expected duplicate Received fields to be consumed bottom-up, got %+v", first)
	}
}

func TestHeaderPicker_PreservesFoldedWhitespace(t *testing.T) {
	headers := header{
		"Subject: Hello\r\n\t world  again\r\n",
	}
	picker := newHeaderPicker(headers)
	instance, ok := picker.pick("subject")
	if !ok {
		t.Fatal("Expected to find the folded Subject field")
	}
	if instance.Raw != headers[0] {
		t.Errorf("Expected folded field to be preserved as %q, got %q", headers[0], instance.Raw)
	}
}
