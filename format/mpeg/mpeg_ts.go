package mpeg

import (
	"github.com/wader/fq/format"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/interp"
	"github.com/wader/fq/pkg/scalar"
)

func init() {
	interp.RegisterFormat(decode.Format{
		Name:        format.MPEG_TS,
		ProbeOrder:  format.ProbeOrderBinFuzzy, // make sure to be after gif, both start with 0x47
		Description: "MPEG Transport Stream",
		Groups:      []string{format.PROBE},
		DecodeFn:    tsDecode,
	})
}

// TODO: ts_packet

const tsPacketLength = 188 * 8

const (
	adaptationFieldControlPayloadOnly               = 0b01
	adaptationFieldControlAdaptationFieldOnly       = 0b10
	adaptationFieldControlAdaptationFieldAndPayload = 0b11
)

func tsDecode(d *decode.D, _ any) any {

	d.FieldArray("packets", func(d *decode.D) {
		for !d.End() {
			d.FramedFn(tsPacketLength, func(d *decode.D) {
				d.FieldStruct("packet", func(d *decode.D) {
					d.FieldU8("sync", d.UintAssert(0x47), scalar.UintHex)
					d.FieldBool("transport_error_indicator")
					payloadUnitStsart := d.FieldBool("payload_unit_start")
					d.FieldBool("transport_priority")
					d.FieldU13("pid")
					d.FieldU2("transport_scrambling_control", scalar.UintMapSymStr{
						0b00: "not_scrambled",
						0b01: "reserved",
						0b10: "even_key",
						0b11: "odd_key",
					})
					adaptationFieldControl := d.FieldU2("adaptation_field_control", scalar.UintMapSymStr{
						0b00:                              "reserved",
						adaptationFieldControlPayloadOnly: "payload_only",
						adaptationFieldControlAdaptationFieldOnly:       "adaptation_field_only",
						adaptationFieldControlAdaptationFieldAndPayload: "adaptation_and_payload",
					})
					d.FieldU4("continuity_counter")

					switch adaptationFieldControl {
					case adaptationFieldControlAdaptationFieldOnly,
						adaptationFieldControlAdaptationFieldAndPayload:
						d.FieldStruct("adaptation_field", func(d *decode.D) {
							d.FieldU8("length")                                                                  //Number of bytes in the adaptation field immediately following this byte
							d.FieldBool("discontinuity_indicator")                                               // Set if current TS packet is in a discontinuity state with respect to either the continuity counter or the program clock reference
							d.FieldBool("random_access_indicator")                                               // Set when the stream may be decoded without errors from this point
							d.FieldBool("elementary_stream_priority_indicator")                                  // Set when this stream should be considered "high priority"
							pcrPresent := d.FieldBool("pcr_present")                                             // Set when PCR field is present
							opcrPresent := d.FieldBool("opcr_present")                                           // Set when OPCR field is present
							splicingPointPresent := d.FieldBool("splicing_point_present")                        // Set when splice countdown field is present
							transportPrivatePresent := d.FieldBool("transport_private_present")                  // Set when transport private data is present
							adaptationFieldExtensionPresent := d.FieldBool("adaptation_field_extension_present") // Set when adaptation extension data is present
							if pcrPresent {
								d.FieldU("pcr", 48)
							}
							if opcrPresent {
								d.FieldU("opcr", 48)
							}
							if splicingPointPresent {
								d.FieldU8("splicing_point")
							}
							if transportPrivatePresent {
								d.FieldStruct("transport_private", func(d *decode.D) {
									length := d.FieldU8("length")
									d.FieldRawLen("data", int64(length)*8)
								})
							}
							if adaptationFieldExtensionPresent {
								d.FieldStruct("adaptation_extension", func(d *decode.D) {
									length := d.FieldU8("length")
									d.FramedFn(int64(length)*8, func(d *decode.D) {
										d.FieldBool("legal_time_window")
										d.FieldBool("piecewise_rate")
										d.FieldBool("seamless_splice")
										d.FieldU5("reserved")
										d.FieldRawLen("data", d.BitsLeft())
									})
								})

								// Optional fields
								// LTW flag set (2 bytes)
								// LTW valid flag	1	0x8000
								// LTW offset	15	0x7fff	Extra information for rebroadcasters to determine the state of buffers when packets may be missing.
								// Piecewise flag set (3 bytes)
								// Reserved	2	0xc00000
								// Piecewise rate	22	0x3fffff	The rate of the stream, measured in 188-byte packets, to define the end-time of the LTW.
								// Seamless splice flag set (5 bytes)
								// Splice type	4	0xf000000000	Indicates the parameters of the H.262 splice.
								// DTS next access unit	36	0x0efffefffe	The PES DTS of the splice point. Split up as multiple fields, 1 marker bit (0x1), 15 bits, 1 marker bit, 15 bits, and 1 marker bit, for 33 data bits total.
							}
						})
					}

					switch adaptationFieldControl {
					case adaptationFieldControlPayloadOnly,
						adaptationFieldControlAdaptationFieldAndPayload:
						d.FieldStruct("payload", func(d *decode.D) {
							var payloadPointer uint64
							if payloadUnitStsart {
								payloadPointer = d.FieldU8("payload_pointer")
							}
							if payloadPointer > 0 {
								d.FieldRawLen("prev_data", int64(payloadPointer)*8)
							}
							d.FieldRawLen("data", d.BitsLeft())
						})
					}
				})
			})
		}
	})

	return nil
}
