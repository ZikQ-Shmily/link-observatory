package main

import "testing"

func TestParseNextTraceWithDiagnosticLinesAndMissingHops(t *testing.T) {
	input := "[NextTrace API] preferred API IP — DMIT.NRT\n" +
		"{\"Hops\":[[{\"Success\":true,\"Address\":{\"IP\":\"10.10.10.1\"},\"TTL\":1,\"RTT\":144241,\"Geo\":{\"whois\":\"RFC1918\"}}],null,\n" +
		"[{\"Success\":true,\"Address\":{\"IP\":\"103.117.100.45\"},\"TTL\":3,\"RTT\":48210000,\"Hostname\":\"HKG.AS3.Pro.TsuenWan\"," +
		"\"Geo\":{\"asnumber\":\"906\",\"country\":\"中国\",\"prov\":\"香港\",\"city\":\"香港\",\"whois\":\"DMITINC-AP\"}}]]}\n\n"
	hops, err := parseNextTrace([]byte(input), 4)
	if err != nil || len(hops) != 2 {
		t.Fatalf("cannot parse NextTrace output: %v %+v", err, hops)
	}
	if hop := hops[1]; hop.TTL != 3 || hop.RTT != 48.21 || hop.ASN != "AS906" ||
		hop.Network != "DMITINC-AP" || hop.Location != "中国 · 香港" || hop.Hostname != "HKG.AS3.Pro.TsuenWan" {
		t.Fatalf("unexpected destination hop: %+v", hop)
	}
}
