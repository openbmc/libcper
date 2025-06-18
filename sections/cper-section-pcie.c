/**
 * Describes functions for converting PCIe CPER sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <stdio.h>
#include <string.h>
#include <json.h>
#include <libcper/base64.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-pcie.h>
#include <libcper/log.h>
#include <string.h>

json_object *pcie_capability_to_ir(EFI_PCIE_ERROR_DATA *pcie_error);
json_object *pcie_aer_to_ir(EFI_PCIE_ERROR_DATA *pcie_error);

#define ANYP 0xFF

struct class_code pci_class_codes[] = {
	// Base Class 00h - Legacy devices
	{ 0x00, 0x00, 0x00,
	  "All currently implemented devices except VGA-compatible devices" },
	{ 0x00, 0x01, 0x00, "VGA-compatible device" },

	// Base Class 01h - Mass storage controllers
	{ 0x01, 0x00, 0x00, "SCSI controller - vendor-specific interface" },
	{ 0x01, 0x00, 0x11,
	  "SCSI storage device - SCSI over PCI Express (SOP) with PQI" },
	{ 0x01, 0x00, 0x12,
	  "SCSI controller - SCSI over PCI Express (SOP) with PQI" },
	{ 0x01, 0x00, 0x13,
	  "SCSI storage device and SCSI controller - SOP with PQI" },
	{ 0x01, 0x00, 0x21,
	  "SCSI storage device - SOP with NVM Express interface" },
	{ 0x01, 0x01, ANYP, "IDE controller" },
	{ 0x01, 0x02, 0x00,
	  "Floppy disk controller - vendor-specific interface" },
	{ 0x01, 0x03, 0x00, "IPI bus controller - vendor-specific interface" },
	{ 0x01, 0x04, 0x00, "RAID controller - vendor-specific interface" },
	{ 0x01, 0x05, 0x20,
	  "ATA controller with ADMA interface - single stepping" },
	{ 0x01, 0x05, 0x30,
	  "ATA controller with ADMA interface - continuous operation" },
	{ 0x01, 0x06, 0x00,
	  "Serial ATA controller - vendor-specific interface" },
	{ 0x01, 0x06, 0x01, "Serial ATA controller - AHCI interface" },
	{ 0x01, 0x06, 0x02, "Serial Storage Bus Interface" },
	{ 0x01, 0x07, 0x00,
	  "Serial Attached SCSI (SAS) controller - vendor specific interface" },
	{ 0x01, 0x08, 0x00,
	  "Non-volatile memory subsystem - vendor-specific interface" },
	{ 0x01, 0x08, 0x01,
	  "Non-volatile memory subsystem - NVMHCI interface" },
	{ 0x01, 0x08, 0x02, "NVM Express (NVMe) I/O controller" },
	{ 0x01, 0x08, 0x03, "NVM Express (NVMe) administrative controller" },
	{ 0x01, 0x09, 0x00,
	  "Universal Flash Storage (UFS) controller - vendor specific interface" },
	{ 0x01, 0x09, 0x01,
	  "Universal Flash Storage (UFS) controller - UFSHCI" },
	{ 0x01, 0x80, 0x00,
	  "Other mass storage controller - vendor-specific interface" },

	// Base Class 02h - Network controllers
	{ 0x02, 0x00, 0x00, "Ethernet controller" },
	{ 0x02, 0x00, 0x01,
	  "Ethernet Controller with IDPF compliant Interface" },
	{ 0x02, 0x01, 0x00, "Token Ring controller" },
	{ 0x02, 0x02, 0x00, "FDDI controller" },
	{ 0x02, 0x03, 0x00, "ATM controller" },
	{ 0x02, 0x04, 0x00, "ISDN controller" },
	{ 0x02, 0x05, 0x00, "WorldFip controller" },
	{ 0x02, 0x06, ANYP, "PICMG 2.14 Multi Computing" },
	{ 0x02, 0x07, 0x00, "InfiniBand Controller" },
	{ 0x02, 0x08, 0x00, "Host fabric controller - vendor-specific" },
	{ 0x02, 0x80, 0x00, "Other network controller" },

	// Base Class 03h - Display controllers
	{ 0x03, 0x00, 0x00, "VGA-compatible controller" },
	{ 0x03, 0x00, 0x01, "8514-compatible controller" },
	{ 0x03, 0x01, 0x00, "XGA controller" },
	{ 0x03, 0x02, 0x00, "3D controller" },
	{ 0x03, 0x80, 0x00, "Other display controller" },

	// Base Class 04h - Multimedia devices
	{ 0x04, 0x00, 0x00, "Video device - vendor specific interface" },
	{ 0x04, 0x01, 0x00, "Audio device - vendor specific interface" },
	{ 0x04, 0x02, 0x00,
	  "Computer telephony device - vendor specific interface" },
	{ 0x04, 0x03, 0x00, "High Definition Audio (HD-A) 1.0 compatible" },
	{ 0x04, 0x03, 0x80,
	  "High Definition Audio (HD-A) 1.0 compatible with vendor extensions" },
	{ 0x04, 0x80, 0x00,
	  "Other multimedia device - vendor specific interface" },
	// Base Class 05h - Memory controllers
	{ 0x05, 0x00, 0x00, "RAM" },
	{ 0x05, 0x01, 0x00, "Flash" },
	{ 0x05, 0x02, 0x00, "CXL Memory Device - vendor specific interface" },
	{ 0x05, 0x02, 0x10,
	  "CXL Memory Device following CXL 2.0 or later specification" },
	{ 0x05, 0x80, 0x00, "Other memory controller" },

	// Base Class 06h - Bridge devices
	{ 0x06, 0x00, 0x00, "Host bridge" },
	{ 0x06, 0x01, 0x00, "ISA bridge" },
	{ 0x06, 0x02, 0x00, "EISA bridge" },
	{ 0x06, 0x03, 0x00, "MCA bridge" },
	{ 0x06, 0x04, 0x00, "PCI-to-PCI bridge" },
	{ 0x06, 0x04, 0x01, "Subtractive Decode PCI-to-PCI bridge" },
	{ 0x06, 0x05, 0x00, "PCMCIA bridge" },
	{ 0x06, 0x06, 0x00, "NuBus bridge" },
	{ 0x06, 0x07, 0x00, "CardBus bridge" },
	{ 0x06, 0x08, ANYP, "RACEway bridge" },
	{ 0x06, 0x09, 0x40,
	  "Semi-transparent PCI-to-PCI bridge - primary bus towards host" },
	{ 0x06, 0x09, 0x80,
	  "Semi-transparent PCI-to-PCI bridge - secondary bus towards host" },
	{ 0x06, 0x0A, 0x00, "InfiniBand-to-PCI host bridge" },
	{ 0x06, 0x0B, 0x00,
	  "Advanced Switching to PCI host bridge - Custom Interface" },
	{ 0x06, 0x0B, 0x01,
	  "Advanced Switching to PCI host bridge - ASI-SIG Defined Portal Interface" },
	{ 0x06, 0x80, 0x00, "Other bridge device" },

	// Base Class 07h - Simple communication controllers
	{ 0x07, 0x00, 0x00, "Generic XT-compatible serial controller" },
	{ 0x07, 0x00, 0x01, "16450-compatible serial controller" },
	{ 0x07, 0x00, 0x02, "16550-compatible serial controller" },
	{ 0x07, 0x00, 0x03, "16650-compatible serial controller" },
	{ 0x07, 0x00, 0x04, "16750-compatible serial controller" },
	{ 0x07, 0x00, 0x05, "16850-compatible serial controller" },
	{ 0x07, 0x00, 0x06, "16950-compatible serial controller" },
	{ 0x07, 0x01, 0x00, "Parallel port" },
	{ 0x07, 0x01, 0x01, "Bi-directional parallel port" },
	{ 0x07, 0x01, 0x02, "ECP 1.X compliant parallel port" },
	{ 0x07, 0x01, 0x03, "IEEE1284 controller" },
	{ 0x07, 0x01, 0xFE, "IEEE1284 target device" },
	{ 0x07, 0x02, 0x00, "Multiport serial controller" },
	{ 0x07, 0x03, 0x00, "Generic modem" },
	{ 0x07, 0x03, 0x01,
	  "Hayes compatible modem - 16450-compatible interface" },
	{ 0x07, 0x03, 0x02,
	  "Hayes compatible modem - 16550-compatible interface" },
	{ 0x07, 0x03, 0x03,
	  "Hayes compatible modem - 16650-compatible interface" },
	{ 0x07, 0x03, 0x04,
	  "Hayes compatible modem - 16750-compatible interface" },
	{ 0x07, 0x04, 0x00, "GPIB (IEEE 488.1/2) controller" },
	{ 0x07, 0x05, 0x00, "Smart Card" },
	{ 0x07, 0x80, 0x00, "Other communications device" },

	// Base Class 08h - Base system peripherals
	{ 0x08, 0x00, 0x00, "Generic 8259 PIC" },
	{ 0x08, 0x00, 0x01, "ISA PIC" },
	{ 0x08, 0x00, 0x02, "EISA PIC" },
	{ 0x08, 0x00, 0x10, "I/O APIC interrupt controller" },
	{ 0x08, 0x00, 0x20, "I/O(x) APIC interrupt controller" },
	{ 0x08, 0x01, 0x00, "Generic 8237 DMA controller" },
	{ 0x08, 0x01, 0x01, "ISA DMA controller" },
	{ 0x08, 0x01, 0x02, "EISA DMA controller" },
	{ 0x08, 0x02, 0x00, "Generic 8254 system timer" },
	{ 0x08, 0x02, 0x01, "ISA system timer" },
	{ 0x08, 0x02, 0x02, "EISA system timers" },
	{ 0x08, 0x02, 0x03, "High Performance Event Timer" },
	{ 0x08, 0x03, 0x00, "Generic RTC controller" },
	{ 0x08, 0x03, 0x01, "ISA RTC controller" },
	{ 0x08, 0x04, 0x00, "Generic PCI Hot-Plug controller" },
	{ 0x08, 0x05, 0x00, "SD Host controller" },
	{ 0x08, 0x06, 0x00, "IOMMU" },
	{ 0x08, 0x07, 0x00, "Root Complex Event Collector" },
	{ 0x08, 0x08, 0x00, "Time Card - vendor-specific interface" },
	{ 0x08, 0x08, 0x01, "Time Card - OCP TAP interface" },
	{ 0x08, 0x80, 0x00, "Other system peripheral" },

	// Base Class 09h - Input devices
	{ 0x09, 0x00, 0x00, "Keyboard controller" },
	{ 0x09, 0x01, 0x00, "Digitizer (pen)" },
	{ 0x09, 0x02, 0x00, "Mouse controller" },
	{ 0x09, 0x03, 0x00, "Scanner controller" },
	{ 0x09, 0x04, 0x00, "Gameport controller (generic)" },
	{ 0x09, 0x04, 0x10, "Gameport controller - legacy ports" },
	{ 0x09, 0x80, 0x00, "Other input controller" },

	// Base Class 0Ah - Docking stations
	{ 0x0A, 0x00, 0x00, "Generic docking station" },
	{ 0x0A, 0x80, 0x00, "Other type of docking station" },

	// Base Class 0Bh - Processors
	{ 0x0B, 0x00, 0x00, "386" },
	{ 0x0B, 0x01, 0x00, "486" },
	{ 0x0B, 0x02, 0x00, "Pentium" },
	{ 0x0B, 0x10, 0x00, "Alpha" },
	{ 0x0B, 0x20, 0x00, "PowerPC" },
	{ 0x0B, 0x30, 0x00, "MIPS" },
	{ 0x0B, 0x40, 0x00, "Co-processor" },
	{ 0x0B, 0x80, 0x00, "Other processors" },

	// Base Class 0Ch - Serial bus controllers
	{ 0x0C, 0x00, 0x00, "IEEE 1394 (FireWire)" },
	{ 0x0C, 0x00, 0x10, "IEEE 1394 following 1394 OpenHCI specification" },
	{ 0x0C, 0x01, 0x00, "ACCESS.bus" },
	{ 0x0C, 0x02, 0x00, "SSA" },
	{ 0x0C, 0x03, 0x00, "USB - Universal Host Controller Specification" },
	{ 0x0C, 0x03, 0x10, "USB - Open Host Controller Specification" },
	{ 0x0C, 0x03, 0x20, "USB2 host controller - Intel EHCI" },
	{ 0x0C, 0x03, 0x30, "USB3 host controller - Intel xHCI" },
	{ 0x0C, 0x03, 0x40, "USB4 Host Interface" },
	{ 0x0C, 0x03, 0x80, "USB - no specific Programming Interface" },
	{ 0x0C, 0x03, 0xFE, "USB device (not host controller)" },
	{ 0x0C, 0x04, 0x00, "Fibre Channel" },
	{ 0x0C, 0x05, 0x00, "SMBus (System Management Bus)" },
	{ 0x0C, 0x07, 0x00, "IPMI SMIC Interface" },
	{ 0x0C, 0x07, 0x01, "IPMI Keyboard Controller Style Interface" },
	{ 0x0C, 0x07, 0x02, "IPMI Block Transfer Interface" },
	{ 0x0C, 0x08, 0x00, "SERCOS Interface Standard" },
	{ 0x0C, 0x09, 0x00, "CANbus" },
	{ 0x0C, 0x0A, 0x00, "MIPI I3C Host Controller Interface" },
	{ 0x0C, 0x0B, 0x00, "CXL Fabric Management Host Interface controller" },
	{ 0x0C, 0x0C, 0x00, "Memory Mapped Buffer Interface (MMBI) endpoint" },
	{ 0x0C, 0x80, 0x00, "Other Serial Bus Controllers" },

	// Base Class 0Dh - Wireless controllers
	{ 0x0D, 0x00, 0x00, "iRDA compatible controller" },
	{ 0x0D, 0x01, 0x00, "Consumer IR controller" },
	{ 0x0D, 0x01, 0x10, "UWB Radio controller" },
	{ 0x0D, 0x10, 0x00, "RF controller" },
	{ 0x0D, 0x11, 0x00, "Bluetooth" },
	{ 0x0D, 0x12, 0x00, "Broadband" },
	{ 0x0D, 0x20, 0x00, "Ethernet (802.11a - 5 GHz)" },
	{ 0x0D, 0x21, 0x00, "Ethernet (802.11b - 2.4 GHz)" },
	{ 0x0D, 0x40, 0x00, "Cellular controller/modem" },
	{ 0x0D, 0x41, 0x00,
	  "Cellular controller/modem plus Ethernet (802.11)" },
	{ 0x0D, 0x80, 0x00, "Other type of wireless controller" },

	// Base Class 0Eh - Intelligent I/O controllers
	{ 0x0E, 0x00, 0x00,
	  "I2O Architecture Specification 1.0 Message FIFO at offset 040h" },
	{ 0x0E, 0x00, ANYP, "Message FIFO at offset 040h" },

	// Base Class 0Fh - Satellite communication controllers
	{ 0x0F, 0x01, 0x00, "TV" },
	{ 0x0F, 0x02, 0x00, "Audio" },
	{ 0x0F, 0x03, 0x00, "Voice" },
	{ 0x0F, 0x04, 0x00, "Data" },
	{ 0x0F, 0x80, 0x00, "Other satellite communication controller" },

	// Base Class 10h - Encryption/Decryption controllers
	{ 0x10, 0x00, 0x00,
	  "Network and computing encryption and decryption controller" },
	{ 0x10, 0x10, 0x00,
	  "Entertainment encryption and decryption controller" },
	{ 0x10, 0x20, 0x00, "Trusted Platform Module (TPM)" },
	{ 0x10, 0x80, 0x00, "Other encryption and decryption controller" },

	// Base Class 11h - Data acquisition and signal processing controllers
	{ 0x11, 0x00, 0x00, "DPIO modules" },
	{ 0x11, 0x01, 0x00, "Performance counters" },
	{ 0x11, 0x10, 0x00,
	  "Communications synchronization plus time and frequency test/measurement" },
	{ 0x11, 0x20, 0x00, "Management card" },
	{ 0x11, 0x80, 0x00,
	  "Other data acquisition/signal processing controllers" },

	// Base Class 12h - Processing accelerators
	{ 0x12, 0x00, 0x00,
	  "Processing Accelerator - vendor-specific interface" },
	{ 0x12, 0x01, 0x00,
	  "SNIA Smart Data Accelerator Interface (SDXI) controller" },

	// Base Class 13h - Non-Essential Instrumentation
	{ 0x13, 0x00, 0x00,
	  "Non-Essential Instrumentation Function - Vendor specific interface" },

	// Base Class FFh - Device does not fit in any defined classes
	{ 0xFF, 0x00, 0x00, "Device does not fit in any defined classes" }
};

const char *get_class_code_name(UINT8 base, UINT8 sub, UINT8 programming)
{
	for (size_t i = 0;
	     i < sizeof(pci_class_codes) / sizeof(pci_class_codes[0]); i++) {
		if (pci_class_codes[i].base == base &&
		    pci_class_codes[i].sub == sub) {
			if (pci_class_codes[i].programming == programming ||
			    pci_class_codes[i].programming == ANYP) {
				return pci_class_codes[i].name;
			}
		}
	}
	return NULL;
}

//Converts a single PCIe CPER section into JSON IR.
json_object *cper_section_pcie_to_ir(const UINT8 *section, UINT32 size,
				     char **desc_string)
{
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	strncpy(*desc_string, "A PCIe Error occurred",
		SECTION_DESC_STRING_SIZE);

	if (size < sizeof(EFI_PCIE_ERROR_DATA)) {
		return NULL;
	}

	EFI_PCIE_ERROR_DATA *pcie_error = (EFI_PCIE_ERROR_DATA *)section;
	json_object *section_ir = json_object_new_object();

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T,
				     .value.ui64 = pcie_error->ValidFields };

	//Port type.
	if (isvalid_prop_to_ir(&ui64Type, 0)) {
		json_object *port_type = integer_to_readable_pair(
			pcie_error->PortType, 9, PCIE_ERROR_PORT_TYPES_KEYS,
			PCIE_ERROR_PORT_TYPES_VALUES, "Unknown");
		json_object_object_add(section_ir, "portType", port_type);
	}

	//Version, provided each half in BCD.
	if (isvalid_prop_to_ir(&ui64Type, 1)) {
		json_object *version = json_object_new_object();
		json_object_object_add(version, "minor",
				       json_object_new_int(bcd_to_int(
					       pcie_error->Version & 0xFF)));
		json_object_object_add(version, "major",
				       json_object_new_int(bcd_to_int(
					       pcie_error->Version >> 8)));
		json_object_object_add(section_ir, "version", version);
	}

	//Command & status.
	if (isvalid_prop_to_ir(&ui64Type, 2)) {
		json_object *command_status = json_object_new_object();
		json_object_object_add(
			command_status, "commandRegister",
			json_object_new_uint64(pcie_error->CommandStatus &
					       0xFFFF));
		json_object_object_add(
			command_status, "statusRegister",
			json_object_new_uint64(pcie_error->CommandStatus >>
					       16));
		json_object_object_add(section_ir, "commandStatus",
				       command_status);
	}

	//PCIe Device ID.
	if (isvalid_prop_to_ir(&ui64Type, 3)) {
		json_object *device_id = json_object_new_object();

		UINT64 class_id = (pcie_error->DevBridge.ClassCode[2] << 16) +
				  (pcie_error->DevBridge.ClassCode[1] << 8) +
				  pcie_error->DevBridge.ClassCode[0];
		const char *class_name =
			get_class_code_name(pcie_error->DevBridge.ClassCode[2],
					    pcie_error->DevBridge.ClassCode[1],
					    pcie_error->DevBridge.ClassCode[0]);
		if (class_name != NULL) {
			json_object_object_add(
				device_id, "class",
				json_object_new_string(class_name));
		}
		add_int_hex_16(device_id, "deviceID_Hex",
			       pcie_error->DevBridge.DeviceId);
		add_int_hex_16(device_id, "vendorID_Hex",
			       pcie_error->DevBridge.VendorId);
		add_int_hex_24(device_id, "classCode_Hex", class_id);
		add_int_hex_8(device_id, "functionNumber_Hex",
			      pcie_error->DevBridge.Function);
		add_int_hex_8(device_id, "deviceNumber_Hex",
			      pcie_error->DevBridge.Device);
		add_int_hex_8(device_id, "segmentNumber_Hex",
			      pcie_error->DevBridge.Segment);
		add_int_hex_8(device_id, "primaryOrDeviceBusNumber_Hex",
			      pcie_error->DevBridge.PrimaryOrDeviceBus);
		add_int_hex_8(device_id, "secondaryBusNumber_Hex",
			      pcie_error->DevBridge.SecondaryBus);
		add_int_hex_8(device_id, "slotNumber_Hex",
			      pcie_error->DevBridge.Slot.Number);
		add_int(device_id, "deviceID", pcie_error->DevBridge.DeviceId);

		add_int(device_id, "vendorID", pcie_error->DevBridge.VendorId);

		add_int(device_id, "classCode", class_id);

		add_int(device_id, "functionNumber",
			pcie_error->DevBridge.Function);

		add_int(device_id, "deviceNumber",
			pcie_error->DevBridge.Device);

		add_int(device_id, "segmentNumber",
			pcie_error->DevBridge.Segment);

		add_int(device_id, "primaryOrDeviceBusNumber",
			pcie_error->DevBridge.PrimaryOrDeviceBus);

		add_int(device_id, "secondaryBusNumber",
			pcie_error->DevBridge.SecondaryBus);

		add_int(device_id, "slotNumber",
			pcie_error->DevBridge.Slot.Number);

		json_object_object_add(section_ir, "deviceID", device_id);
	}

	//Device serial number.
	if (isvalid_prop_to_ir(&ui64Type, 4)) {
		json_object_object_add(
			section_ir, "deviceSerialNumber",
			json_object_new_uint64(pcie_error->SerialNo));
	}

	//Bridge control status.
	if (isvalid_prop_to_ir(&ui64Type, 5)) {
		json_object *bridge_control_status = json_object_new_object();
		json_object_object_add(
			bridge_control_status, "secondaryStatusRegister",
			json_object_new_uint64(pcie_error->BridgeControlStatus &
					       0xFFFF));
		json_object_object_add(
			bridge_control_status, "controlRegister",
			json_object_new_uint64(
				pcie_error->BridgeControlStatus >> 16));
		json_object_object_add(section_ir, "bridgeControlStatus",
				       bridge_control_status);
	}

	//Capability structure.
	//The PCIe capability structure provided here could either be PCIe 1.1 Capability Structure
	//(36-byte, padded to 60 bytes) or PCIe 2.0 Capability Structure (60-byte).
	//Check the PCIe Capabilities Registers (offset 0x2) to determine the capability version.
	if (isvalid_prop_to_ir(&ui64Type, 6)) {
		json_object_object_add(section_ir, "capabilityStructure",
				       pcie_capability_to_ir(pcie_error));
	}

	//AER information.
	if (isvalid_prop_to_ir(&ui64Type, 7)) {
		json_object_object_add(section_ir, "aerInfo",
				       pcie_aer_to_ir(pcie_error));
	}

	return section_ir;
}

//Converts PCIe Capability Structure section into JSON IR.
json_object *pcie_capability_to_ir(EFI_PCIE_ERROR_DATA *pcie_error)
{
	int32_t encoded_len = 0;
	char *encoded = NULL;
	json_object *pcie_capability_ir = json_object_new_object();

	encoded = base64_encode((UINT8 *)pcie_error->Capability.PcieCap, 60,
				&encoded_len);
	if (encoded == NULL) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		json_object_object_add(pcie_capability_ir, "data",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	json_object *fields_ir;
	capability_registers *cap_decode;
	cap_decode = (capability_registers *)&pcie_error->Capability.PcieCap;

	/*
	 * PCI Express Capability Structure Header
	 * Offset: 0x0
	 */
	fields_ir = json_object_new_object();
	pcie_capability_header_t *pcie_cap_header =
		&cap_decode->pcie_capability_header;
	add_dict(fields_ir, "capability_id", pcie_cap_header->capability_id,
		 NULL, 0);
	add_int(fields_ir, "next_capability_pointer",
		pcie_cap_header->next_capability_pointer);
	json_object_object_add(pcie_capability_ir, "pcie_capability_header",
			       fields_ir);

	/*
	 * PCI Express Capabilities Register
	 * Offset: 0x2
	 */
	fields_ir = json_object_new_object();
	pcie_capabilities_t *pcie_cap = &cap_decode->pcie_capabilities;
	add_int(fields_ir, "capability_version", pcie_cap->capability_version);
	add_dict(fields_ir, "device_port_type", pcie_cap->device_port_type,
		 device_port_type_dict, device_port_type_dict_size);
	add_bool(fields_ir, "slot_implemented", pcie_cap->slot_implemented);
	add_int(fields_ir, "interrupt_message_number",
		pcie_cap->interrupt_message_number);
	//add_int(fields_ir, "undefined", pcie_cap->undefined);
	add_bool_enum(fields_ir, "flit_mode_supported", supported_dict,
		      pcie_cap->flit_mode_supported);
	json_object_object_add(pcie_capability_ir, "pcie_capabilities",
			       fields_ir);

	/*
	 * Device Capabilities Register
	 * Offset: 0x4
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "max_payload_size_supported",
		cap_decode->device_capabilities.max_payload_size_supported);
	add_bool_enum(
		fields_ir, "phantom_functions_supported", supported_dict,
		cap_decode->device_capabilities.phantom_functions_supported);
	add_bool_enum(
		fields_ir, "extended_tag_field_supported", supported_dict,
		cap_decode->device_capabilities.extended_tag_field_supported);
	add_dict(
		fields_ir, "endpoint_l0s_acceptable_latency",
		cap_decode->device_capabilities.endpoint_l0s_acceptable_latency,
		NULL, 0);
	add_dict(fields_ir, "endpoint_l1_acceptable_latency",
		 cap_decode->device_capabilities.endpoint_l1_acceptable_latency,
		 NULL, 0);
	//add_int(fields_ir, "undefined",
	//	cap_decode->device_capabilities.undefined);
	add_bool(fields_ir, "role_based_error_reporting",
		 cap_decode->device_capabilities.role_based_error_reporting);
	add_bool(fields_ir, "err_cor_subclass_capable",
		 cap_decode->device_capabilities.err_cor_subclass_capable);
	add_int(fields_ir, "rx_mps_fixed",
		cap_decode->device_capabilities.rx_mps_fixed);
	add_int(fields_ir, "captured_slot_power_limit_value",
		cap_decode->device_capabilities.captured_slot_power_limit_value);
	add_int(fields_ir, "captured_slot_power_limit_scale",
		cap_decode->device_capabilities.captured_slot_power_limit_scale);
	add_bool_enum(
		fields_ir, "function_level_reset_capability_supported",
		supported_dict,
		cap_decode->device_capabilities.function_level_reset_capability);
	add_bool_enum(fields_ir, "mixed_mps_supported", supported_dict,
		      cap_decode->device_capabilities.mixed_mps_supported);
	add_bool_enum(fields_ir, "tee_io_supported", supported_dict,
		      cap_decode->device_capabilities.tee_io_supported);
	//add_int(fields_ir, "rsvdp", cap_decode->device_capabilities.rsvdp);
	json_object_object_add(pcie_capability_ir, "device_capabilities",
			       fields_ir);

	/*
	 * Device Control Register
	 * Offset: 0x8
	 */
	fields_ir = json_object_new_object();
	add_bool_enum(
		fields_ir, "correctable_error_reporting_enable", enabled_dict,
		cap_decode->device_control.correctable_error_reporting_enable);
	add_bool_enum(
		fields_ir, "non_fatal_error_reporting_enable", enabled_dict,
		cap_decode->device_control.non_fatal_error_reporting_enable);
	add_bool_enum(fields_ir, "fatal_error_reporting_enable", enabled_dict,
		      cap_decode->device_control.fatal_error_reporting_enable);
	add_bool_enum(
		fields_ir, "unsupported_request_reporting_enabled",
		enabled_dict,
		cap_decode->device_control.unsupported_request_reporting_enable);
	add_bool_enum(fields_ir, "relaxed_ordering_enable", enabled_dict,
		      cap_decode->device_control.enable_relaxed_ordering);
	add_int(fields_ir, "max_payload_size",
		cap_decode->device_control.max_payload_size);
	add_bool_enum(fields_ir, "extended_tag_field_enable", enabled_dict,
		      cap_decode->device_control.extended_tag_field_enable);
	add_bool_enum(fields_ir, "phantom_functions_enable", enabled_dict,
		      cap_decode->device_control.phantom_functions_enable);
	add_bool_enum(fields_ir, "aux_power_pm_enable", enabled_dict,
		      cap_decode->device_control.aux_power_pm_enable);
	add_int(fields_ir, "enable_no_snoop",
		cap_decode->device_control.enable_no_snoop);
	add_int(fields_ir, "max_read_request_size",
		cap_decode->device_control.max_read_request_size);
	add_bool(fields_ir, "function_level_reset",
		 cap_decode->device_control.function_level_reset);
	json_object_object_add(pcie_capability_ir, "device_control", fields_ir);

	/*
	 * Device Status Register
	 * Offset: 0xA
	 */
	fields_ir = json_object_new_object();
	add_bool(fields_ir, "correctable_error_detected",
		 cap_decode->device_status.correctable_error_detected);
	add_bool(fields_ir, "non_fatal_error_detected",
		 cap_decode->device_status.non_fatal_error_detected);
	add_bool(fields_ir, "fatal_error_detected",
		 cap_decode->device_status.fatal_error_detected);
	add_bool(fields_ir, "unsupported_request_detected",
		 cap_decode->device_status.unsupported_request_detected);
	add_bool(fields_ir, "aux_power_detected",
		 cap_decode->device_status.aux_power_detected);
	add_bool(fields_ir, "transactions_pending",
		 cap_decode->device_status.transactions_pending);
	add_int(fields_ir, "emergency_power_reduction",
		cap_decode->device_status.emergency_power_reduction);
	//add_int(fields_ir, "rsvdz", cap_decode->device_status.rsvdz);
	json_object_object_add(pcie_capability_ir, "device_status", fields_ir);

	/*
	 * Link Capabilities Register
	 * Offset: 0xC
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "max_link_speed",
		cap_decode->link_capabilities.max_link_speed);
	add_int(fields_ir, "maximum_link_width",
		cap_decode->link_capabilities.maximum_link_width);
	add_int(fields_ir, "aspm_support",
		cap_decode->link_capabilities.aspm_support);
	add_int(fields_ir, "l0s_exit_latency",
		cap_decode->link_capabilities.l0s_exit_latency);
	add_int(fields_ir, "l1_exit_latency",
		cap_decode->link_capabilities.l1_exit_latency);
	add_bool(fields_ir, "clock_power_management",
		 cap_decode->link_capabilities.clock_power_management);
	add_bool(fields_ir, "surprise_down_error_reporting_capable",
		 cap_decode->link_capabilities
			 .surprise_down_error_reporting_capable);
	add_bool(fields_ir, "data_link_layer_link_active_reporting_capable",
		 cap_decode->link_capabilities
			 .data_link_layer_link_active_reporting_capable);
	add_bool(fields_ir, "link_bandwidth_notification_capability",
		 cap_decode->link_capabilities
			 .link_bandwidth_notification_capability);
	add_bool(fields_ir, "aspm_optionality_compliance",
		 cap_decode->link_capabilities.aspm_optionality_compliance);
	//add_int(fields_ir, "rsvdp", cap_decode->link_capabilities.rsvdp);
	add_int(fields_ir, "port_number",
		cap_decode->link_capabilities.port_number);
	json_object_object_add(pcie_capability_ir, "link_capabilities",
			       fields_ir);

	/*
	 * Link Control Register
	 * Offset: 0x10
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "aspm_control",
		cap_decode->link_control.aspm_control);
	add_bool(fields_ir, "ptm_prop_delay_adaptation_interpretation",
		 cap_decode->link_control
			 .ptm_prop_delay_adaptation_interpretation);
	//add_bool(fields_ir, "read_completion_boundary",
	//	 cap_decode->link_control.read_completion_boundary);
	add_int(fields_ir, "link_disable",
		cap_decode->link_control.link_disable);
	add_int(fields_ir, "retrain_link",
		cap_decode->link_control.retrain_link);
	//add_bool(fields_ir, "common_clock_configuration",
	//	 cap_decode->link_control.common_clock_configuration);
	add_int(fields_ir, "extended_synch",
		cap_decode->link_control.extended_synch);
	//add_bool(fields_ir, "enable_clock_power_management",
	//	 cap_decode->link_control.enable_clock_power_management);
	//add_bool(fields_ir, "hardware_autonomous_width_disable",
	//	 cap_decode->link_control.hardware_autonomous_width_disable);
	//add_bool(fields_ir, "link_bandwidth_management_interrupt_enable",
	//	 cap_decode->link_control
	//		 .link_bandwidth_management_interrupt_enable);
	//add_bool(fields_ir, "link_autonomous_bandwidth_interrupt_enable",
	//	 cap_decode->link_control
	//		 .link_autonomous_bandwidth_interrupt_enable);
	add_int(fields_ir, "sris_clocking",
		cap_decode->link_control.sris_clocking);
	add_int(fields_ir, "flit_mode_disable",
		cap_decode->link_control.flit_mode_disable);
	//add_bool(fields_ir, "drs_signaling_control",
	//	 cap_decode->link_control.drs_signaling_control);
	json_object_object_add(pcie_capability_ir, "link_control", fields_ir);

	/*
	 * Link Status Register
	 * Offset: 0x12
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "current_link_speed",
		cap_decode->link_status.current_link_speed);
	add_int(fields_ir, "negotiated_link_width",
		cap_decode->link_status.negotiated_link_width);
	//add_int(fields_ir, "undefined", cap_decode->link_status.undefined);
	add_int(fields_ir, "link_training",
		cap_decode->link_status.link_training);
	//add_bool(fields_ir, "slot_clock_configuration",
	//	 cap_decode->link_status.slot_clock_configuration);
	//add_bool(fields_ir, "data_link_layer_link_active",
	//	 cap_decode->link_status.data_link_layer_link_active);
	//add_bool(fields_ir, "link_bandwidth_management_status",
	//	 cap_decode->link_status.link_bandwidth_management_status);
	//add_bool(fields_ir, "link_autonomous_bandwidth_status",
	//	 cap_decode->link_status.link_autonomous_bandwidth_status);
	json_object_object_add(pcie_capability_ir, "link_status", fields_ir);

	/*
	 * Slot Capabilities Register
	 * Offset: 0x14
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "attention_button_present",
	//	 cap_decode->slot_capabilities.attention_button_present);
	//add_bool(fields_ir, "power_controller_present",
	//	 cap_decode->slot_capabilities.power_controller_present);
	//add_bool(fields_ir, "mrl_sensor_present",
	//	 cap_decode->slot_capabilities.mrl_sensor_present);
	//add_bool(fields_ir, "attention_indicator_present",
	//	 cap_decode->slot_capabilities.attention_indicator_present);
	//add_bool(fields_ir, "power_indicator_present",
	//	 cap_decode->slot_capabilities.power_indicator_present);
	//add_bool(fields_ir, "hot_plug_surprise",
	//	 cap_decode->slot_capabilities.hot_plug_surprise);
	//add_bool(fields_ir, "hot_plug_capable",
	//	 cap_decode->slot_capabilities.hot_plug_capable);
	add_dict(fields_ir, "slot_power_limit_value",
		 cap_decode->slot_capabilities.slot_power_limit_value, NULL, 0);
	add_int(fields_ir, "slot_power_limit_scale",
		cap_decode->slot_capabilities.slot_power_limit_scale);
	//add_bool(fields_ir, "electromechanical_interlock_present",
	//	 cap_decode->slot_capabilities
	//		 .electromechanical_interlock_present);
	//add_bool(fields_ir, "no_command_completed_support",
	//	 cap_decode->slot_capabilities.no_command_completed_support);
	add_int(fields_ir, "physical_slot_number",
		cap_decode->slot_capabilities.physical_slot_number);
	json_object_object_add(pcie_capability_ir, "slot_capabilities",
			       fields_ir);

	/*
	 * Slot Control Register
	 * Offset: 0x18
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "attention_button_pressed_enable",
	//	 cap_decode->slot_control.attention_button_pressed_enable);
	//add_bool(fields_ir, "power_fault_detected_enable",
	//	 cap_decode->slot_control.power_fault_detected_enable);
	//add_bool(fields_ir, "mrl_sensor_changed_enable",
	//	 cap_decode->slot_control.mrl_sensor_changed_enable);
	//add_bool(fields_ir, "presence_detect_changed_enable",
	//	 cap_decode->slot_control.presence_detect_changed_enable);
	//add_bool(fields_ir, "command_completed_interrupt_enable",
	//	 cap_decode->slot_control.command_completed_interrupt_enable);
	//add_bool(fields_ir, "hot_plug_interrupt_enable",
	//	 cap_decode->slot_control.hot_plug_interrupt_enable);
	add_int(fields_ir, "attention_indicator_control",
		cap_decode->slot_control.attention_indicator_control);
	add_int(fields_ir, "power_indicator_control",
		cap_decode->slot_control.power_indicator_control);
	//add_bool(fields_ir, "power_controller_control",
	//	 cap_decode->slot_control.power_controller_control);
	//add_bool(fields_ir, "electromechanical_interlock_control",
	//	 cap_decode->slot_control.electromechanical_interlock_control);
	//add_bool(fields_ir, "data_link_layer_state_changed_enable",
	//	 cap_decode->slot_control.data_link_layer_state_changed_enable);
	//add_bool(fields_ir, "auto_slot_power_limit_disable",
	//	 cap_decode->slot_control.auto_slot_power_limit_disable);
	//add_bool(fields_ir, "in_band_pd_disable",
	//	 cap_decode->slot_control.in_band_pd_disable);
	add_int(fields_ir, "rsvdp", cap_decode->slot_control.rsvdp);
	json_object_object_add(pcie_capability_ir, "slot_control", fields_ir);

	/*
	 * Slot Status Register
	 * Offset: 0x1A
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "attention_button_pressed",
	//	 cap_decode->slot_status.attention_button_pressed);
	//add_bool(fields_ir, "power_fault_detected",
	//	 cap_decode->slot_status.power_fault_detected);
	add_int(fields_ir, "mrl_sensor_changed",
		cap_decode->slot_status.mrl_sensor_changed);
	//add_bool(fields_ir, "presence_detect_changed",
	//	 cap_decode->slot_status.presence_detect_changed);
	add_int(fields_ir, "command_completed",
		cap_decode->slot_status.command_completed);
	add_int(fields_ir, "mrl_sensor_state",
		cap_decode->slot_status.mrl_sensor_state);
	//add_bool(fields_ir, "presence_detect_state",
	//	 cap_decode->slot_status.presence_detect_state);
	//add_bool(fields_ir, "electromechanical_interlock_status",
	//	 cap_decode->slot_status.electromechanical_interlock_status);
	//add_bool(fields_ir, "data_link_layer_state_changed",
	//	 cap_decode->slot_status.data_link_layer_state_changed);
	//add_int(fields_ir, "rsvdz", cap_decode->slot_status.rsvdz);
	json_object_object_add(pcie_capability_ir, "slot_status", fields_ir);

	/*
	 * Root Control Register
	 * Offset: 0x1C
	 */
	//fields_ir = json_object_new_object();
	//add_bool(fields_ir, "system_error_on_correctable_error_enable",
	//	 cap_decode->root_control
	//		 .system_error_on_correctable_error_enable);
	//add_bool(
	//	fields_ir, "system_error_on_non_fatal_error_enable",
	//	cap_decode->root_control.system_error_on_non_fatal_error_enable);
	//add_bool(fields_ir, "system_error_on_fatal_error_enable",
	//	 cap_decode->root_control.system_error_on_fatal_error_enable);
	//add_bool(fields_ir, "pme_interrupt_enable",
	//	 cap_decode->root_control.pme_interrupt_enable);
	//add_bool(fields_ir, "configuration_rrs_software_visibility_enable",
	//	 cap_decode->root_control
	//		 .configuration_rrs_software_visibility_enable);
	//add_bool(fields_ir, "no_nfm_subtree_below_this_root_port",
	//	 cap_decode->root_control.no_nfm_subtree_below_this_root_port);
	//add_int(fields_ir, "rsvdp", cap_decode->root_control.rsvdp);
	//json_object_object_add(pcie_capability_ir, "root_control", fields_ir);

	/*
	 * Root Capabilities Register
	 * Offset: 0x1E
	 */
	//fields_ir = json_object_new_object();
	//add_bool(fields_ir, "configuraton_rrs_software_visibility",
	//	 cap_decode->root_capabilities
	//		 .configuraton_rrs_software_visibility);
	//add_int(fields_ir, "rsvdp", cap_decode->root_capabilities.rsvdp);
	//json_object_object_add(pcie_capability_ir, "root_capabilities",
	//		       fields_ir);

	/*
	 * Root Status Register
	 * Offset: 0x20
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "pme_requester_id",
		cap_decode->root_status.pme_requester_id);
	add_int(fields_ir, "pme_status", cap_decode->root_status.pme_status);
	add_int(fields_ir, "pme_pending", cap_decode->root_status.pme_pending);
	//add_int(fields_ir, "rsvdp", cap_decode->root_status.rsvdp);
	json_object_object_add(pcie_capability_ir, "root_status", fields_ir);

	if (cap_decode->pcie_capabilities.capability_version < 2) {
		return pcie_capability_ir;
	}

	/*
	 * Device Capabilities 2 Register
	 * Offset: 0x24
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "completion_timeout_ranges_supported",
		cap_decode->device_capabilities2
			.completion_timeout_ranges_supported);
	add_bool_enum(fields_ir, "completion_timeout_disable_supported",
		      supported_dict,
		      cap_decode->device_capabilities2
			      .completion_timeout_disable_supported);
	add_bool_enum(
		fields_ir, "ari_forwarding_supported", supported_dict,
		cap_decode->device_capabilities2.ari_forwarding_supported);
	add_bool_enum(
		fields_ir, "atomic_op_routing_supported", supported_dict,
		cap_decode->device_capabilities2.atomic_op_routing_supported);
	add_bool_enum(fields_ir, "_32_bit_atomicop_completer_supported",
		      supported_dict,
		      cap_decode->device_capabilities2
			      ._32_bit_atomicop_completer_supported);
	add_bool_enum(fields_ir, "_64_bit_atomicop_completer_supported",
		      supported_dict,
		      cap_decode->device_capabilities2
			      ._64_bit_atomicop_completer_supported);
	add_bool_enum(fields_ir, "_128_bit_cas_completer_supported",
		      supported_dict,
		      cap_decode->device_capabilities2
			      ._128_bit_cas_completer_supported);
	add_bool_enum(
		fields_ir, "no_ro_enabled_pr_pr_passing", passing_dict,
		cap_decode->device_capabilities2.no_ro_enabled_pr_pr_passing);
	add_bool_enum(fields_ir, "ltr_mechanism_supported", supported_dict,
		      cap_decode->device_capabilities2.ltr_mechanism_supported);
	add_bool_enum(fields_ir, "tph_completer_supported", supported_dict,
		      cap_decode->device_capabilities2.tph_completer_supported);
	//add_int(fields_ir, "undefined",
	//	cap_decode->device_capabilities2.undefined);
	//add_bool(fields_ir, "_10_bit_tag_completer_supported",
	//	 cap_decode->device_capabilities2
	//		 ._10_bit_tag_completer_supported);
	//add_bool(fields_ir, "_10_bit_tag_requester_supported",
	//	 cap_decode->device_capabilities2
	//		 ._10_bit_tag_requester_supported);
	add_bool_enum(fields_ir, "obff_supported", supported_dict,
		      cap_decode->device_capabilities2.obff_supported);
	//add_bool(fields_ir, "extended_fmt_field_supported",
	//	 cap_decode->device_capabilities2.extended_fmt_field_supported);
	//add_bool(fields_ir, "end_end_tlp_prefix_supported",
	//	 cap_decode->device_capabilities2.end_end_tlp_prefix_supported);
	add_dict(fields_ir, "max_end_end_tlp_prefixes",
		 cap_decode->device_capabilities2.max_end_end_tlp_prefixes,
		 NULL, 0);
	add_bool_enum(fields_ir, "emergency_power_reduction_supported",
		      supported_dict,
		      cap_decode->device_capabilities2
			      .emergency_power_reduction_supported);
	//add_bool(fields_ir, "emergency_power_reduction_init_required",
	//	 cap_decode->device_capabilities2
	//		 .emergency_power_reduction_init_required);
	//add_int(fields_ir, "rsvdp", cap_decode->device_capabilities2.rsvdp);
	//add_bool(fields_ir, "dmwr_completer_supported",
	//	 cap_decode->device_capabilities2.dmwr_completer_supported);
	add_int(fields_ir, "dmwr_lengths_supported",
		cap_decode->device_capabilities2.dmwr_lengths_supported);
	//add_bool(fields_ir, "frs_supported",
	//	 cap_decode->device_capabilities2.frs_supported);
	json_object_object_add(pcie_capability_ir, "device_capabilities2",
			       fields_ir);

	/*
	 * Device Control 2 Register
	 * Offset: 0x28
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "completion_timeout_value",
		cap_decode->device_control2.completion_timeout_value);
	//add_bool(fields_ir, "completion_timeout_disable",
	//	 cap_decode->device_control2.completion_timeout_disable);
	add_bool(fields_ir, "ari_forwarding_enable",
		 cap_decode->device_control2.ari_forwarding_enable);
	add_bool(fields_ir, "atomicop_requester_enable",
		 cap_decode->device_control2.atomicop_requester_enable);
	add_bool(fields_ir, "atomicop_egress_blocking",
		 cap_decode->device_control2.atomicop_egress_blocking);
	add_bool(fields_ir, "ido_request_enable",
		 cap_decode->device_control2.ido_request_enable);
	add_bool(fields_ir, "ido_completion_enable",
		 cap_decode->device_control2.ido_completion_enable);
	add_bool(fields_ir, "ltr_mechanism_enable",
		 cap_decode->device_control2.ltr_mechanism_enable);
	add_bool(fields_ir, "emergency_power_reduction_request",
		 cap_decode->device_control2.emergency_power_reduction_request);
	add_bool(fields_ir, "10_bit_tag_requester_enable",
		 cap_decode->device_control2._10_bit_tag_requester_enable);
	add_int(fields_ir, "obff_enable",
		cap_decode->device_control2.obff_enable);
	//add_bool(fields_ir, "end_end_tlp_prefix_blocking",
	//	 cap_decode->device_control2.end_end_tlp_prefix_blocking);
	json_object_object_add(pcie_capability_ir, "device_control2",
			       fields_ir);

	/*
	 * Device Status 2 Register
	 * Offset: 0x2A
	 */
	//fields_ir = json_object_new_object();
	//add_int(fields_ir, "rsvdz", cap_decode->device_status2.rsvdz);
	//json_object_object_add(pcie_capability_ir, "device_status2", fields_ir);

	/*
	 * Link Capabilities 2 Register
	 * Offset: 0x2C
	 */
	fields_ir = json_object_new_object();
	//add_int(fields_ir, "rsvdp", cap_decode->link_capabilities2.rsvdp);
	add_int(fields_ir, "supported_link_speeds",
		cap_decode->link_capabilities2.supported_link_speeds_register);
	add_bool_enum(fields_ir, "crosslink_supported", supported_dict,
		      cap_decode->link_capabilities2.crosslink_supported);
	add_int(fields_ir, "lower_skp_os_generation_supported",
		cap_decode->link_capabilities2
			.lower_skp_os_generation_supported);
	add_int(fields_ir, "lower_skp_os_reception_supported",
		cap_decode->link_capabilities2.lower_skp_os_reception_supported);
	add_bool_enum(fields_ir, "retimer_presence_detect_supported",
		      supported_dict,
		      cap_decode->link_capabilities2
			      .retimer_presence_detect_supported);
	add_bool_enum(fields_ir, "two_retimers_presence_detect_supported",
		      supported_dict,
		      cap_decode->link_capabilities2
			      .two_retimers_presence_detect_supported);
	//add_int(fields_ir, "reserved", cap_decode->link_capabilities2.reserved);
	add_bool_enum(fields_ir, "drs_supported", supported_dict,
		      cap_decode->link_capabilities2.drs_supported);
	json_object_object_add(pcie_capability_ir, "link_capabilities2",
			       fields_ir);

	/*
	 * Link Control 2 Register
	 * Offset: 0x30
	 */
	fields_ir = json_object_new_object();
	add_dict(fields_ir, "target_link_speed",
		 cap_decode->link_control2.target_link_speed, NULL, 0);
	add_bool_enum(fields_ir, "enter_compliance", supported_dict,
		      cap_decode->link_control2.enter_compliance);
	add_dict(fields_ir, "hardware_autonomous_speed_disable",
		 cap_decode->link_control2.hardware_autonomous_speed_disable,
		 NULL, 0);
	add_bool(fields_ir, "selectable_de_emphasis",
		 cap_decode->link_control2.selectable_de_emphasis);
	add_int(fields_ir, "transmit_margin",
		cap_decode->link_control2.transmit_margin);
	add_bool(fields_ir, "enter_modified_compliance",
		 cap_decode->link_control2.enter_modified_compliance);
	add_bool(fields_ir, "compliance_sos",
		 cap_decode->link_control2.compliance_sos);
	add_int(fields_ir, "compliance_preset_de_emphasis",
		cap_decode->link_control2.compliance_preset_de_emphasis);
	json_object_object_add(pcie_capability_ir, "link_control2", fields_ir);

	/*
	 * Link Status 2 Register
	 * Offset: 0x32
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "current_de_emphasis_level",
		cap_decode->link_status2.current_de_emphasis_level);
	add_bool(fields_ir, "equalization_8gts_complete",
		 cap_decode->link_status2.equalization_8gts_complete);
	add_bool(fields_ir, "equalization_8gts_phase1_successful",
		 cap_decode->link_status2.equalization_8gts_phase1_successful);
	add_bool(fields_ir, "equalization_8gts_phase2_successful",
		 cap_decode->link_status2.equalization_8gts_phase2_successful);
	add_bool(fields_ir, "equalization_8gts_phase3_successful",
		 cap_decode->link_status2.equalization_8gts_phase3_successful);
	add_bool(fields_ir, "link_equalization_request_8gts",
		 cap_decode->link_status2.link_equalization_request_8gts);
	add_bool(fields_ir, "retimer_presence_detected",
		 cap_decode->link_status2.retimer_presence_detected);
	add_bool(fields_ir, "two_retimers_presence_detected",
		 cap_decode->link_status2.two_retimers_presence_detected);
	add_int(fields_ir, "crosslink_resolution",
		cap_decode->link_status2.crosslink_resolution);
	add_int(fields_ir, "flit_mode_status",
		cap_decode->link_status2.flit_mode_status);
	//add_int(fields_ir, "rsvdz", cap_decode->link_status2.rsvdz);
	add_int(fields_ir, "downstream_component_presence",
		cap_decode->link_status2.downstream_component_presence);
	add_bool(fields_ir, "drs_message_received",
		 cap_decode->link_status2.drs_message_received);
	json_object_object_add(pcie_capability_ir, "link_status2", fields_ir);

	/*
	 * Slot Capabilities 2 Register
	 * Offset: 0x34
	 */
	//fields_ir = json_object_new_object();
	//add_int(fields_ir, "rsvdp", cap_decode->slot_capabilities2.rsvdp);
	//json_object_object_add(pcie_capability_ir, "slot_capabilities2",
	//		       fields_ir);

	/*
	 * Slot Control 2 Register
	 * Offset: 0x38
	 */
	//fields_ir = json_object_new_object();
	//add_int(fields_ir, "rsvdp", cap_decode->slot_control2.rsvdp);
	//json_object_object_add(pcie_capability_ir, "slot_control2", fields_ir);

	/*
	 * Slot Status 2 Register
	 * Offset: 0x3A
	 */
	//fields_ir = json_object_new_object();
	//add_int(fields_ir, "rsvdp", cap_decode->slot_status2.rsvdp);
	//json_object_object_add(pcie_capability_ir, "slot_status2", fields_ir);

	return pcie_capability_ir;
}

//Converts PCIe Capability Structure section into JSON IR.
json_object *pcie_aer_to_ir(EFI_PCIE_ERROR_DATA *pcie_error)
{
	int32_t encoded_len = 0;
	char *encoded = NULL;
	json_object *aer_capability_ir = json_object_new_object();

	encoded = base64_encode((UINT8 *)pcie_error->AerInfo.PcieAer, 96,
				&encoded_len);
	if (encoded == NULL) {
		printf("Failed to allocate encode output buffer. \n");
	} else {
		json_object_object_add(aer_capability_ir, "data",
				       json_object_new_string_len(encoded,
								  encoded_len));
		free(encoded);
	}

	json_object *fields_ir;

	aer_info_registers *aer_decode;
	aer_decode = (aer_info_registers *)&pcie_error->AerInfo.PcieAer;

	/*
	 * AER Capability Header
	 * Offset: 0x0
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "capability_id",
		aer_decode->capability_header.capability_id);
	add_int(fields_ir, "capability_version",
		aer_decode->capability_header.capability_version);
	add_int(fields_ir, "next_capability_offset",
		aer_decode->capability_header.next_capability_offset);
	json_object_object_add(aer_capability_ir, "capability_header",
			       fields_ir);

	/*
	 * Uncorrectable Error Status Register
	 * Offset: 0x4
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "undefined",
	//	 aer_decode->uncorrectable_error_status.undefined);
	//add_int(fields_ir, "rsvdz1",
	//	aer_decode->uncorrectable_error_status.rsvdz1);
	add_bool(fields_ir, "data_link_protocol_error_status",
		 aer_decode->uncorrectable_error_status
			 .data_link_protocol_error_status);
	add_bool(fields_ir, "surprise_down_error_status",
		 aer_decode->uncorrectable_error_status
			 .surprise_down_error_status);
	//add_int(fields_ir, "rsvdz2",
	//	aer_decode->uncorrectable_error_status.rsvdz2);
	add_bool(fields_ir, "poisoned_tlp_received",
		 aer_decode->uncorrectable_error_status.poisoned_tlp_received);
	add_bool(fields_ir, "flow_control_protocol_error_status",
		 aer_decode->uncorrectable_error_status
			 .flow_control_protocol_error_status);
	add_bool(fields_ir, "completion_timeout_status",
		 aer_decode->uncorrectable_error_status
			 .completion_timeout_status);
	add_bool(fields_ir, "completer_abort_status",
		 aer_decode->uncorrectable_error_status.completer_abort_status);
	add_bool(fields_ir, "unexpected_completion_status",
		 aer_decode->uncorrectable_error_status
			 .unexpected_completion_status);
	add_bool(
		fields_ir, "receiver_overflow_status",
		aer_decode->uncorrectable_error_status.receiver_overflow_status);
	add_bool(fields_ir, "malformed_tlp_status",
		 aer_decode->uncorrectable_error_status.malformed_tlp_status);
	add_bool(fields_ir, "ecrc_error_status",
		 aer_decode->uncorrectable_error_status.ecrc_error_status);
	add_bool(fields_ir, "unsupported_request_error_status",
		 aer_decode->uncorrectable_error_status
			 .unsupported_request_error_status);
	add_bool(fields_ir, "acs_violation_status",
		 aer_decode->uncorrectable_error_status.acs_violation_status);
	add_bool(fields_ir, "uncorrectable_internal_error_status",
		 aer_decode->uncorrectable_error_status
			 .uncorrectable_internal_error_status);
	add_bool(fields_ir, "mc_blocked_tlp_status",
		 aer_decode->uncorrectable_error_status.mc_blocked_tlp_status);
	add_bool(fields_ir, "atomicop_egress_blocked_status",
		 aer_decode->uncorrectable_error_status
			 .atomicop_egress_blocked_status);
	add_bool(fields_ir, "tlp_prefix_blocked_error_status",
		 aer_decode->uncorrectable_error_status
			 .tlp_prefix_blocked_error_status);
	add_bool(fields_ir, "poisoned_tlp_egress_blocked_status",
		 aer_decode->uncorrectable_error_status
			 .poisoned_tlp_egress_blocked_status);
	add_bool(fields_ir, "dmwr_request_egress_blocked_status",
		 aer_decode->uncorrectable_error_status
			 .dmwr_request_egress_blocked_status);
	add_bool(
		fields_ir, "ide_check_failed_status",
		aer_decode->uncorrectable_error_status.ide_check_failed_status);
	add_bool(
		fields_ir, "misrouted_ide_tlp_status",
		aer_decode->uncorrectable_error_status.misrouted_ide_tlp_status);
	add_bool(
		fields_ir, "pcrc_check_failed_status",
		aer_decode->uncorrectable_error_status.pcrc_check_failed_status);
	add_bool(fields_ir, "tlp_translation_egress_blocked_status",
		 aer_decode->uncorrectable_error_status
			 .tlp_translation_egress_blocked_status);
	json_object_object_add(aer_capability_ir, "uncorrectable_error_status",
			       fields_ir);

	/*
	 * Uncorrectable Error Mask Register
	 * Offset: 0x8
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "undefined",
	//	 aer_decode->uncorrectable_error_mask.undefined);
	//add_int(fields_ir, "rsvdz1",
	//	aer_decode->uncorrectable_error_mask.rsvdz1);
	add_int(fields_ir, "data_link_protocol_error_mask",
		aer_decode->uncorrectable_error_mask
			.data_link_protocol_error_mask);
	add_int(fields_ir, "surprise_down_error_mask",
		aer_decode->uncorrectable_error_mask.surprise_down_error_mask);
	//add_int(fields_ir, "rsvdz2",
	//	aer_decode->uncorrectable_error_mask.rsvdz2);
	add_int(fields_ir, "poisoned_tlp_received_mask",
		aer_decode->uncorrectable_error_mask.poisoned_tlp_received_mask);
	add_int(fields_ir, "flow_control_protocol_error_mask",
		aer_decode->uncorrectable_error_mask
			.flow_control_protocol_error_mask);
	add_int(fields_ir, "completion_timeout_mask",
		aer_decode->uncorrectable_error_mask.completion_timeout_mask);
	add_int(fields_ir, "completer_abort_mask",
		aer_decode->uncorrectable_error_mask.completer_abort_mask);
	add_int(fields_ir, "unexpected_completion_mask",
		aer_decode->uncorrectable_error_mask.unexpected_completion_mask);
	add_int(fields_ir, "receiver_overflow_mask",
		aer_decode->uncorrectable_error_mask.receiver_overflow_mask);
	add_int(fields_ir, "malformed_tlp_mask",
		aer_decode->uncorrectable_error_mask.malformed_tlp_mask);
	add_int(fields_ir, "ecrc_error_mask",
		aer_decode->uncorrectable_error_mask.ecrc_error_mask);
	add_int(fields_ir, "unsupported_request_error_mask",
		aer_decode->uncorrectable_error_mask
			.unsupported_request_error_mask);
	add_int(fields_ir, "acs_violation_mask",
		aer_decode->uncorrectable_error_mask.acs_violation_mask);
	add_int(fields_ir, "uncorrectable_internal_error_mask",
		aer_decode->uncorrectable_error_mask
			.uncorrectable_internal_error_mask);
	add_int(fields_ir, "mc_blocked_tlp_mask",
		aer_decode->uncorrectable_error_mask.mc_blocked_tlp_mask);
	add_int(fields_ir, "atomicop_egress_blocked_mask",
		aer_decode->uncorrectable_error_mask
			.atomicop_egress_blocked_mask);
	add_int(fields_ir, "tlp_prefix_blocked_error_mask",
		aer_decode->uncorrectable_error_mask
			.tlp_prefix_blocked_error_mask);
	add_int(fields_ir, "poisoned_tlp_egress_blocked_mask",
		aer_decode->uncorrectable_error_mask
			.poisoned_tlp_egress_blocked_mask);
	add_int(fields_ir, "dmwr_request_egress_blocked_mask",
		aer_decode->uncorrectable_error_mask
			.dmwr_request_egress_blocked_mask);
	add_int(fields_ir, "ide_check_failed_mask",
		aer_decode->uncorrectable_error_mask.ide_check_failed_mask);
	add_int(fields_ir, "misrouted_ide_tlp_mask",
		aer_decode->uncorrectable_error_mask.misrouted_ide_tlp_mask);
	add_int(fields_ir, "pcrc_check_failed_mask",
		aer_decode->uncorrectable_error_mask.pcrc_check_failed_mask);
	add_int(fields_ir, "tlp_translation_egress_blocked_mask",
		aer_decode->uncorrectable_error_mask
			.tlp_translation_egress_blocked_mask);
	json_object_object_add(aer_capability_ir, "uncorrectable_error_mask",
			       fields_ir);

	/*
	 * Uncorrectable Error Severity Register
	 * Offset: 0xC
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "undefined",
	//	 aer_decode->uncorrectable_error_severity.undefined);
	//add_int(fields_ir, "rsvdz1",
	//	aer_decode->uncorrectable_error_severity.rsvdz1);
	add_bool_enum(fields_ir, "data_link_protocol_error_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .data_link_protocol_error_severity);
	add_bool_enum(fields_ir, "surprise_down_error_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .surprise_down_error_severity);
	//add_int(fields_ir, "rsvdz2",
	//	aer_decode->uncorrectable_error_severity.rsvdz2);
	add_bool_enum(fields_ir, "poisoned_tlp_received_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .poisoned_tlp_received_severity);
	add_bool_enum(fields_ir, "flow_control_protocol_error_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .flow_control_protocol_error_severity);
	add_bool_enum(fields_ir, "completion_timeout_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .completion_timeout_severity);
	add_bool_enum(fields_ir, "completer_abort_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .completer_abort_severity);
	add_bool_enum(fields_ir, "unexpected_completion_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .unexpected_completion_severity);
	add_bool_enum(fields_ir, "receiver_overflow_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .receiver_overflow_severity);
	add_bool_enum(
		fields_ir, "malformed_tlp_severity", severity_dict,
		aer_decode->uncorrectable_error_severity.malformed_tlp_severity);
	add_bool_enum(
		fields_ir, "ecrc_error_severity", severity_dict,
		aer_decode->uncorrectable_error_severity.ecrc_error_severity);
	add_bool_enum(fields_ir, "unsupported_request_error_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .unsupported_request_error_severity);
	add_bool_enum(
		fields_ir, "acs_violation_severity", severity_dict,
		aer_decode->uncorrectable_error_severity.acs_violation_severity);
	add_bool_enum(fields_ir, "uncorrectable_internal_error_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .uncorrectable_internal_error_severity);
	add_bool_enum(fields_ir, "mc_blocked_tlp_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .mc_blocked_tlp_severity);
	add_bool_enum(fields_ir, "atomicop_egress_blocked_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .atomicop_egress_blocked_severity);
	add_bool_enum(fields_ir, "tlp_prefix_blocked_error_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .tlp_prefix_blocked_error_severity);
	add_bool_enum(fields_ir, "poisoned_tlp_egress_blocked_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .poisoned_tlp_egress_blocked_severity);
	add_bool_enum(fields_ir, "dmwr_request_egress_blocked_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .dmwr_request_egress_blocked_severity);
	add_bool_enum(fields_ir, "ide_check_failed_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .ide_check_failed_severity);
	add_bool_enum(fields_ir, "misrouted_ide_tlp_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .misrouted_ide_tlp_severity);
	add_bool_enum(fields_ir, "pcrc_check_failed_severity", severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .pcrc_check_failed_severity);
	add_bool_enum(fields_ir, "tlp_translation_egress_blocked_severity",
		      severity_dict,
		      aer_decode->uncorrectable_error_severity
			      .tlp_translation_egress_blocked_severity);
	json_object_object_add(aer_capability_ir,
			       "uncorrectable_error_severity", fields_ir);

	/*
	 * Correctable Error Status Register
	 * Offset: 0x10
	 */
	fields_ir = json_object_new_object();
	add_bool(fields_ir, "receiver_error_status",
		 aer_decode->correctable_error_status.receiver_error_status);
	//add_int(fields_ir, "rsvdz1",
	//	aer_decode->correctable_error_status.rsvdz1);
	add_bool(fields_ir, "bad_tlp_status",
		 aer_decode->correctable_error_status.bad_tlp_status);
	add_bool(fields_ir, "bad_dllp_status",
		 aer_decode->correctable_error_status.bad_dllp_status);
	add_bool(
		fields_ir, "replay_num_rollover_status",
		aer_decode->correctable_error_status.replay_num_rollover_status);
	//add_int(fields_ir, "rsvdz2",
	//	aer_decode->correctable_error_status.rsvdz2);
	add_bool(fields_ir, "replay_timer_timeout_status",
		 aer_decode->correctable_error_status
			 .replay_timer_timeout_status);
	add_bool(fields_ir, "advisory_non_fatal_error_status",
		 aer_decode->correctable_error_status
			 .advisory_non_fatal_error_status);
	add_bool(fields_ir, "corrected_internal_error_status",
		 aer_decode->correctable_error_status
			 .corrected_internal_error_status);
	add_bool(
		fields_ir, "header_log_overflow_status",
		aer_decode->correctable_error_status.header_log_overflow_status);
	//add_int(fields_ir, "rsvdz3",
	//	aer_decode->correctable_error_status.rsvdz3);
	json_object_object_add(aer_capability_ir, "correctable_error_status",
			       fields_ir);

	/*
	 * Correctable Error Mask Register
	 * Offset: 0x14
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "receiver_error_mask",
		aer_decode->correctable_error_mask.receiver_error_mask);
	//add_int(fields_ir, "rsvdz1", aer_decode->correctable_error_mask.rsvdz1);
	add_int(fields_ir, "bad_tlp_mask",
		aer_decode->correctable_error_mask.bad_tlp_mask);
	add_int(fields_ir, "bad_dllp_mask",
		aer_decode->correctable_error_mask.bad_dllp_mask);
	add_int(fields_ir, "replay_num_rollover_mask",
		aer_decode->correctable_error_mask.replay_num_rollover_mask);
	//add_int(fields_ir, "rsvdz2", aer_decode->correctable_error_mask.rsvdz2);
	add_int(fields_ir, "replay_timer_timeout_mask",
		aer_decode->correctable_error_mask.replay_timer_timeout_mask);
	add_int(fields_ir, "advisory_non_fatal_error_mask",
		aer_decode->correctable_error_mask
			.advisory_non_fatal_error_mask);
	add_int(fields_ir, "corrected_internal_error_mask",
		aer_decode->correctable_error_mask
			.corrected_internal_error_mask);
	add_int(fields_ir, "header_log_overflow_mask",
		aer_decode->correctable_error_mask.header_log_overflow_mask);
	//add_int(fields_ir, "rsvdz3", aer_decode->correctable_error_mask.rsvdz3);
	json_object_object_add(aer_capability_ir, "correctable_error_mask",
			       fields_ir);

	/*
	 * Advanced Error Capabilities and Control Register
	 * Offset: 0x18
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "first_error_pointer",
		aer_decode->advanced_error_capabilities_and_control
			.first_error_pointer);
	//add_bool(fields_ir, "ecrc_generation_capable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .ecrc_generation_capable);
	//add_bool(fields_ir, "ecrc_generation_enable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .ecrc_generation_enable);
	//add_bool(fields_ir, "ecrc_check_capable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .ecrc_check_capable);
	//add_bool(fields_ir, "ecrc_check_enable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .ecrc_check_enable);
	//add_bool(fields_ir, "multiple_header_recording_capable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .multiple_header_recording_capable);
	//add_bool(fields_ir, "multiple_header_recording_enable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .multiple_header_recording_enable);
	//add_bool(fields_ir, "tlp_prefix_log_present",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .tlp_prefix_log_present);
	//add_bool(fields_ir, "completion_timeout_prefix_header_log_capable",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .completion_timeout_prefix_header_log_capable);
	add_int(fields_ir, "header_log_size",
		aer_decode->advanced_error_capabilities_and_control
			.header_log_size);
	//add_bool(fields_ir, "logged_tlp_was_flit_mode",
	//	 aer_decode->advanced_error_capabilities_and_control
	//		 .logged_tlp_was_flit_mode);
	add_int(fields_ir, "logged_tlp_size",
		aer_decode->advanced_error_capabilities_and_control
			.logged_tlp_size);
	//add_int(fields_ir, "rsvdp",
	//	aer_decode->advanced_error_capabilities_and_control.rsvdp);
	json_object_object_add(aer_capability_ir,
			       "advanced_error_capabilities_and_control",
			       fields_ir);

	/*
	 * Root Error Command Register
	 * Offset: 0x2C
	 */
	//fields_ir = json_object_new_object();
	//add_bool(fields_ir, "correctable_error_reporting_enable",
	//	 aer_decode->root_error_command
	//		 .correctable_error_reporting_enable);
	//add_bool(
	//	fields_ir, "non_fatal_error_reporting_enable",
	//	aer_decode->root_error_command.non_fatal_error_reporting_enable);
	//add_bool(fields_ir, "fatal_error_reporting_enable",
	//	 aer_decode->root_error_command.fatal_error_reporting_enable);
	//add_int(fields_ir, "rsvdp", aer_decode->root_error_command.rsvdp);
	///json_object_object_add(aer_capability_ir, "root_error_command",
	//		       fields_ir);

	/*
	 * Root Error Status Register
	 * Offset: 0x30
	 */
	fields_ir = json_object_new_object();
	//add_bool(fields_ir, "err_cor_received",
	//	 aer_decode->root_error_status.err_cor_received);
	//add_bool(fields_ir, "multiple_err_cor_received",
	//	 aer_decode->root_error_status.multiple_err_cor_received);
	//add_bool(fields_ir, "err_fatal_nonfatal_received",
	//	 aer_decode->root_error_status.err_fatal_nonfatal_received);
	//add_bool(fields_ir, "multiple_err_fatal_nonfatal_received",
	//	 aer_decode->root_error_status
	//		 .multiple_err_fatal_nonfatal_received);
	//add_bool(fields_ir, "first_uncorrectable_fatal",
	//	 aer_decode->root_error_status.first_uncorrectable_fatal);
	//add_bool(
	//	fields_ir, "non_fatal_error_messages_received",
	//	aer_decode->root_error_status.non_fatal_error_messages_received);
	//add_bool(fields_ir, "fatal_error_messages_received",
	//	 aer_decode->root_error_status.fatal_error_messages_received);
	add_int(fields_ir, "err_cor_subclass",
		aer_decode->root_error_status.err_cor_subclass);
	//add_int(fields_ir, "rsvdz", aer_decode->root_error_status.rsvdz);
	add_int(fields_ir, "advanced_error_interrupt_message_number",
		aer_decode->root_error_status
			.advanced_error_interrupt_message_number);
	json_object_object_add(aer_capability_ir, "root_error_status",
			       fields_ir);

	/*
	 * Error Source Identification Register
	 * Offset: 0x34
	 */
	fields_ir = json_object_new_object();
	add_int(fields_ir, "err_cor_source_identification",
		aer_decode->error_source_id.err_cor_source_identification);
	add_int(fields_ir, "err_fatal_nonfatal_source_identification",
		aer_decode->error_source_id
			.err_fatal_nonfatal_source_identification);
	json_object_object_add(aer_capability_ir, "error_source_id", fields_ir);

	return aer_capability_ir;
}

//Converts a single CPER-JSON PCIe section into CPER binary, outputting to the given stream.
void ir_section_pcie_to_cper(json_object *section, FILE *out)
{
	EFI_PCIE_ERROR_DATA *section_cper =
		(EFI_PCIE_ERROR_DATA *)calloc(1, sizeof(EFI_PCIE_ERROR_DATA));

	//Validation bits.
	ValidationTypes ui64Type = { UINT_64T, .value.ui64 = 0 };
	struct json_object *obj = NULL;

	//Version.
	if (json_object_object_get_ex(section, "version", &obj)) {
		const json_object *version = obj;
		UINT32 minor = int_to_bcd(json_object_get_int(
			json_object_object_get(version, "minor")));
		UINT32 major = int_to_bcd(json_object_get_int(
			json_object_object_get(version, "major")));
		section_cper->Version = minor + (major << 8);
		add_to_valid_bitfield(&ui64Type, 1);
	}

	//Command/status registers.
	if (json_object_object_get_ex(section, "commandStatus", &obj)) {
		const json_object *command_status = obj;
		UINT32 command = (UINT16)json_object_get_uint64(
			json_object_object_get(command_status,
					       "commandRegister"));
		UINT32 status = (UINT16)json_object_get_uint64(
			json_object_object_get(command_status,
					       "statusRegister"));
		section_cper->CommandStatus = command + (status << 16);
		add_to_valid_bitfield(&ui64Type, 2);
	}

	//Device ID.
	if (json_object_object_get_ex(section, "deviceID", &obj)) {
		const json_object *device_id = obj;
		UINT64 class_id = json_object_get_uint64(
			json_object_object_get(device_id, "classCode"));
		section_cper->DevBridge.VendorId =
			(UINT16)json_object_get_uint64(
				json_object_object_get(device_id, "vendorID"));
		section_cper->DevBridge.DeviceId =
			(UINT16)json_object_get_uint64(
				json_object_object_get(device_id, "deviceID"));
		section_cper->DevBridge.ClassCode[2] = class_id >> 16;
		section_cper->DevBridge.ClassCode[1] = (class_id >> 8) & 0xFF;
		section_cper->DevBridge.ClassCode[0] = class_id & 0xFF;
		section_cper->DevBridge.Function =
			(UINT8)json_object_get_uint64(json_object_object_get(
				device_id, "functionNumber"));
		section_cper->DevBridge.Device = (UINT8)json_object_get_uint64(
			json_object_object_get(device_id, "deviceNumber"));
		section_cper->DevBridge.Segment =
			(UINT16)json_object_get_uint64(json_object_object_get(
				device_id, "segmentNumber"));
		section_cper->DevBridge.PrimaryOrDeviceBus =
			(UINT8)json_object_get_uint64(json_object_object_get(
				device_id, "primaryOrDeviceBusNumber"));
		section_cper->DevBridge.SecondaryBus =
			(UINT8)json_object_get_uint64(json_object_object_get(
				device_id, "secondaryBusNumber"));
		section_cper->DevBridge.Slot.Number =
			(UINT16)json_object_get_uint64(json_object_object_get(
				device_id, "slotNumber"));
		add_to_valid_bitfield(&ui64Type, 3);
	}

	//Bridge/control status.
	if (json_object_object_get_ex(section, "bridgeControlStatus", &obj)) {
		const json_object *bridge_control = obj;
		UINT32 bridge_status = (UINT16)json_object_get_uint64(
			json_object_object_get(bridge_control,
					       "secondaryStatusRegister"));
		UINT32 control_status = (UINT16)json_object_get_uint64(
			json_object_object_get(bridge_control,
					       "controlRegister"));
		section_cper->BridgeControlStatus =
			bridge_status + (control_status << 16);
		add_to_valid_bitfield(&ui64Type, 5);
	}

	//Capability structure.
	int32_t decoded_len = 0;
	UINT8 *decoded = NULL;
	json_object *encoded = NULL;
	if (json_object_object_get_ex(section, "capabilityStructure", &obj)) {
		const json_object *capability = obj;
		encoded = json_object_object_get(capability, "data");

		decoded = base64_decode(json_object_get_string(encoded),
					json_object_get_string_len(encoded),
					&decoded_len);
		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			memcpy(section_cper->Capability.PcieCap, decoded,
			       decoded_len);
			free(decoded);
		}
		add_to_valid_bitfield(&ui64Type, 6);
	}

	decoded = NULL;
	encoded = NULL;
	//AER capability structure.
	if (json_object_object_get_ex(section, "aerInfo", &obj)) {
		const json_object *aer_info = obj;
		encoded = json_object_object_get(aer_info, "data");
		decoded_len = 0;

		decoded = base64_decode(json_object_get_string(encoded),
					json_object_get_string_len(encoded),
					&decoded_len);

		if (decoded == NULL) {
			cper_print_log(
				"Failed to allocate decode output buffer. \n");
		} else {
			memcpy(section_cper->AerInfo.PcieAer, decoded,
			       decoded_len);
			free(decoded);
		}
		add_to_valid_bitfield(&ui64Type, 7);
	}

	//Miscellaneous value fields.
	if (json_object_object_get_ex(section, "portType", &obj)) {
		section_cper->PortType = (UINT32)readable_pair_to_integer(obj);
		add_to_valid_bitfield(&ui64Type, 0);
	}
	if (json_object_object_get_ex(section, "deviceSerialNumber", &obj)) {
		section_cper->SerialNo = json_object_get_uint64(obj);
		add_to_valid_bitfield(&ui64Type, 4);
	}

	section_cper->ValidFields = ui64Type.value.ui64;

	//Write out to stream, free resources.
	fwrite(section_cper, sizeof(EFI_PCIE_ERROR_DATA), 1, out);
	fflush(out);
	free(section_cper);
}
