# vmcsreverse

## Overview

LKM designed to dump the exact layout of VMCS. Attempts to VMWRITE a constant
to a writable field, then VMCLEAR for ensuring that it is on memory.
This gives the offset of the field and is performed for all writable fields.
Currently we do not support for obtaining the offset of read-only data fields,
but we plan to implement this feature in the near future.

## Usage

Installation

```
$ make
$ insmod vmcs_reverse.ko
```

Obtaining the offset of VMCS fields which are writable.

```
$ cat /dev/vmcs_reverse
```

Removal

```
$ rmmod vmcs_reverse
$ make clean
```

## Format

```
vmcs_revision_id: VMCS_REVISION_ID_DECIMAL
VMCS_FIELD_ENCODING_HEX: VMCS_FIELD_OFFSET_DECIMAL
...
```

## References

- Graziano, M., Lanzi, A. and Balzarotti, D.: Hypervisor Memory Forensics, Research in Attacks, Intrusions, and Defenses (Stolfo, S. J., Stavrou, A. and Wright, C. V.,eds.), Berlin, Heidelberg, Springer Berlin Heidelberg, pp.21–40 (2013).
- [google/rekall](https://github.com/google/rekall/tree/master/tools/linux/vmcs_layout)
