package xexloaderwv;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class XEXPatchDescriptor {
	public int size;
	public int target_version_value;
	public int source_version_value;
	public byte[] digest_source = new byte[0x14];
	public byte[] image_key_source = new byte[0x10];
	public int size_of_target_headers;
	public int delta_headers_source_offset;
	public int delta_headers_source_size;
	public int delta_headers_target_offset;
	public int delta_image_source_offset;
	public int delta_image_source_size;
	public int delta_image_target_offset;
	public byte[] records;

	public XEXPatchDescriptor(byte[] data) throws IOException {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		size = b.readInt(0);
		if (size < 0x4C || size > data.length) {
			throw new IOException("Invalid XEXP delta descriptor size: " + size);
		}
		target_version_value = b.readInt(4);
		source_version_value = b.readInt(8);
		digest_source = b.readByteArray(0x0C, 0x14);
		image_key_source = b.readByteArray(0x20, 0x10);
		size_of_target_headers = b.readInt(0x30);
		delta_headers_source_offset = b.readInt(0x34);
		delta_headers_source_size = b.readInt(0x38);
		delta_headers_target_offset = b.readInt(0x3C);
		delta_image_source_offset = b.readInt(0x40);
		delta_image_source_size = b.readInt(0x44);
		delta_image_target_offset = b.readInt(0x48);
		records = b.readByteArray(0x4C, size - 0x4C);
	}
}
