package hqc

// Concatenated code: Reed-Solomon + duplicated Reed-Muller.
// Encode: RS encode the message, then RM encode each RS symbol.
// Decode: RM decode each symbol, then RS decode the result.

// codeEncode encodes a message m (K bytes) into a concatenated codeword em (vecN1N2Size64 uint64s).
func codeEncode(p *params, em []uint64, m []uint8) {
	tmp := make([]uint8, p.vecN1SizeBytes)
	defer ZeroBytes(tmp)
	rsEncode(p, tmp, m)
	rmEncode(p, em, tmp)
}

// codeDecode decodes a concatenated codeword em back to a message m (K bytes).
func codeDecode(p *params, m []uint8, em []uint64) {
	tmp := make([]uint8, p.vecN1SizeBytes)
	defer ZeroBytes(tmp)
	rmDecode(p, tmp, em)
	rsDecode(p, m, tmp)
}
