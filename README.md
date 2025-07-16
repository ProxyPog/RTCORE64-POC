extending kdmapper (detected trash)
this project abuses TRCore64.sys which is installed manually or MSI afterburner, which has the osposed device object of \\.\RTCore64
the driver esposes its ioctl coms which then allows arbitrary r/w of kernel memory, which i am abusing to map kernel objects without validation

overview:
Arbitrary kernel read/write via RTCore64 IOCTLs.
Load unsigned .sys drivers directly into kernel memory.
Basic PE loader with relocation support.
DSE bypass on supported Windows versions.
Minimal dependencies: no external kernel components required (other than RTCore64.sys).

usage:
binaryname.exe myunsigneddriver.sys
