package pe

// https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/

import (
	"github.com/wader/fq/format"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/interp"
	"github.com/wader/fq/pkg/scalar"
)

// TODO: probe?

func init() {
	interp.RegisterFormat(decode.Format{
		Name:        format.PE_MSDOS_STUB, // TODO: not PE_ prefix?
		Description: "MS-DOS Stub",
		DecodeFn:    msDosStubDecode,
	})
}

func msDosStubDecode(d *decode.D, _ any) any {
	d.Endian = decode.LittleEndian

	d.FieldU16("e_magic", scalar.Description("Magic number"), d.AssertU(0x5a4d), scalar.ActualHex)
	d.FieldU16("e_cblp", scalar.Description("Bytes on last page of file"))
	d.FieldU16("e_cp", scalar.Description("Pages in file"))
	d.FieldU16("e_crlc", scalar.Description("Relocations"))
	d.FieldU16("e_cparhdr", scalar.Description("Size of header in paragraphs"))
	d.FieldU16("e_minalloc", scalar.Description("Minimum extra paragraphs needed"))
	d.FieldU16("e_maxalloc", scalar.Description("Maximum extra paragraphs needed"))
	d.FieldU16("e_ss", scalar.Description("Initial (relative) SS value"))
	d.FieldU16("e_sp", scalar.Description("Initial SP value"))
	d.FieldU16("e_csum", scalar.Description("Checksum"))
	d.FieldU16("e_ip", scalar.Description("Initial IP value"))
	d.FieldU16("e_cs", scalar.Description("Initial (relative) CS value"))
	d.FieldU16("e_lfarlc", scalar.Description("File address of relocation table"))
	d.FieldU16("e_ovno", scalar.Description("Overlay number"))
	d.FieldRawLen("e_res", 4*16, scalar.Description("Reserved words"))
	d.FieldU16("e_oemid", scalar.Description("OEM identifier (for e_oeminfo)"))
	d.FieldU16("e_oeminfo", scalar.Description("OEM information; e_oemid specific"))
	d.FieldRawLen("e_res2", 10*16, scalar.Description("Reserved words"))
	lfanew := d.FieldU32("e_lfanew", scalar.Description("File address of new exe header"))

	// TODO: x86 format in the future
	d.FieldRawLen("stub", 64*8, scalar.Description("Sub program"))

	subEndPos := d.Pos()

	// TODO: is not padding i guess?
	padding := lfanew*8 - uint64(subEndPos)
	d.FieldRawLen("padding", int64(padding))

	return nil
}
