# CPER JSON Representation & Conversion Library

This repository specifies a structure for representing UEFI CPER records (as
described in UEFI Specification Appendix N) in a human-readable JSON format, in
addition to a library which can readily convert back and forth between the
standard CPER binary format and the specified structured JSON.

## Prerequisites

Before building this library and its associated tools, you must have meson
(>=1.1.1)

## Building

This project uses Meson (>=1.1.1). To build for native architecture, simply run:

```
meson setup build
ninji -C build
```

## Usage

This project comes with several binaries to help you deal with CPER binary and
CPER-JSON. The first of these is `cper-convert`, which is a command line tool
that can be found in `build/`. With this, you can convert to and from CPER and
CPER-JSON through the command line. An example usage scenario is below:

```
cper-convert to-cper samples/cper-json-test-arm.json --out cper.dump
cper-convert to-json cper.generated.dump
```

Another tool bundled with this repository is `cper-generate`, found in `build/`.
This allows you to generate pseudo-random valid CPER records with sections of
specified types for testing purposes. An example use of the program is below:

```
cper-generate --out cper.generated.dump --sections generic ia32x64
```

Help for both of these tools can be accessed through using the `--help` flag in
isolation.

Finally, a static library containing symbols for converting CPER and CPER-JSON
between an intermediate JSON format can be found generated at
`lib/libcper-parse.a`. This contains the following useful library symbols:

```
json_object* cper_to_ir(FILE* cper_file);
void ir_to_cper(json_object* ir, FILE* out);
```

## Specification

The specification for this project's CPER-JSON format can be found in
`specification/`, defined in both JSON Schema format and also as a LaTeX
document. Specification for the CPER binary format can be found in
[UEFI Specification Appendix N](https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf)
(2021/03/18).

## Usage Examples

This library is utilised in a proof of concept displaying CPER communication
between a SatMC and OpenBMC board, including a conversion into CPER JSON for
logging that utilises this library. You can find information on how to reproduce
the prototype at the
[scripts repository](https://gitlab.arm.com/server_management/cper-poc-scripts),
and example usage of the library itself at the
[pldm](https://gitlab.arm.com/server_management/pldm) repository.
