# cper-generator

This project allows you to generate pseudo-random CPER records for software
testing purposes. The records are compliant (to an extent) with the CPER
definitions present within UEFI Specification Appendix N.

## Usage

An example usage of `cper-generator` is shown below.

```sh
cper-generator --out mycper.dump --sections generic dmarvtd ia32x64 arm
```

This command would generate a CPER log with a processor generic section, VT-d
DMAr section, IA32x64 section and an ARM section, outputting to the given
`mycper.dump` file. To see all available names and other command switches, you
can run `cper-generator --help`.

## Caveats

The generator is not completely random within the bounds of the specification,
to make testing easier.

- Validation bits are always set to "true" for **optional** fields, to ensure
  that translating from CPER binary -> JSON -> CPER binary yields the same
  binary output as started with, rather than changing due to optional fields
  being left out.
- Parts of sections which are defined in other external specifications (i.e, not
  included in UEFI Appendix N) generally do not have their structures to
  specification, and are simply random bytes.
