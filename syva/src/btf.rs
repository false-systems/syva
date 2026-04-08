//! Minimal BTF parser for kernel struct field offset resolution.
//!
//! Replaces pahole subprocess calls. Reads /sys/kernel/btf/vmlinux directly
//! and resolves struct field offsets from the BTF type information.
//!
//! Only implements what Syva needs: find a struct by name, find a member
//! by name, return its byte offset. No full BTF library.

use std::path::Path;

const BTF_MAGIC: u16 = 0xEB9F;

// BTF type kinds (from include/uapi/linux/btf.h)
const BTF_KIND_STRUCT: u32 = 4;

/// Parsed BTF data from /sys/kernel/btf/vmlinux.
pub struct BtfData {
    type_section: Vec<u8>,
    string_section: Vec<u8>,
}

/// A BTF struct member: name and byte offset.
struct BtfStructMember {
    name: String,
    offset_bytes: u32,
}

impl BtfData {
    /// Load and parse BTF from a file (typically /sys/kernel/btf/vmlinux).
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read BTF from {}: {e}", path.display()))?;
        Self::parse(&data)
    }

    /// Load BTF from the default kernel path.
    pub fn from_sys_fs() -> anyhow::Result<Self> {
        Self::from_file(Path::new("/sys/kernel/btf/vmlinux"))
    }

    fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 24 {
            anyhow::bail!("BTF data too short for header");
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            anyhow::bail!("invalid BTF magic: {magic:#06x} (expected {BTF_MAGIC:#06x})");
        }

        // Header fields (all little-endian u32 after magic + version + flags)
        let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let type_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let type_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let str_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let str_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

        if hdr_len < 24 || hdr_len > data.len() {
            anyhow::bail!("invalid BTF header length: {hdr_len}");
        }

        let base = hdr_len;
        let section_range = |off: usize, len: usize| -> anyhow::Result<(usize, usize)> {
            let start = base.checked_add(off)
                .ok_or_else(|| anyhow::anyhow!("BTF section offset overflow"))?;
            let end = start.checked_add(len)
                .ok_or_else(|| anyhow::anyhow!("BTF section length overflow"))?;
            if end > data.len() {
                anyhow::bail!("BTF section offsets exceed data length");
            }
            Ok((start, end))
        };

        let (type_start, type_end) = section_range(type_off, type_len)?;
        let (str_start, str_end) = section_range(str_off, str_len)?;

        Ok(Self {
            type_section: data[type_start..type_end].to_vec(),
            string_section: data[str_start..str_end].to_vec(),
        })
    }

    fn string_at(&self, offset: u32) -> &str {
        let start = offset as usize;
        if start >= self.string_section.len() {
            return "";
        }
        let end = self.string_section[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(self.string_section.len());
        std::str::from_utf8(&self.string_section[start..end]).unwrap_or("")
    }

    /// Resolve a struct field's byte offset from BTF.
    /// Returns None if the struct or field is not found.
    pub fn struct_field_offset(&self, struct_name: &str, field_name: &str) -> Option<u32> {
        let members = self.find_struct_members(struct_name)?;
        members.iter()
            .find(|m| m.name == field_name)
            .map(|m| m.offset_bytes)
    }

    /// Walk the type section to find a struct by name and extract its members.
    fn find_struct_members(&self, name: &str) -> Option<Vec<BtfStructMember>> {
        let data = &self.type_section;
        let mut pos = 0;

        while pos + 12 <= data.len() {
            let name_off = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let info = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let _size_or_type = u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);

            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let kind_flag = (info >> 31) & 1;

            pos += 12; // advance past the common header

            if kind == BTF_KIND_STRUCT {
                let type_name = self.string_at(name_off);
                if type_name == name {
                    // Read vlen members, each 12 bytes
                    let mut members = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let mpos = pos + i * 12;
                        if mpos + 12 > data.len() {
                            return None;
                        }
                        let m_name_off = u32::from_le_bytes([data[mpos], data[mpos + 1], data[mpos + 2], data[mpos + 3]]);
                        // skip btf_type (4 bytes)
                        let m_offset = u32::from_le_bytes([data[mpos + 8], data[mpos + 9], data[mpos + 10], data[mpos + 11]]);

                        // In BTF, btf_member.offset is always stored in bits.
                        // When kind_flag is set, the high 8 bits encode bitfield
                        // size and the low 24 bits encode the bit offset.
                        let offset_bytes = if kind_flag != 0 {
                            (m_offset & 0x00ffffff) / 8
                        } else {
                            debug_assert_eq!(m_offset % 8, 0, "non-bitfield member offset must be byte-aligned");
                            m_offset / 8
                        };

                        members.push(BtfStructMember {
                            name: self.string_at(m_name_off).to_string(),
                            offset_bytes,
                        });
                    }
                    return Some(members);
                }
                // Skip member data for non-matching struct
                pos += vlen * 12;
            } else {
                // Skip variable-length data for other type kinds
                pos += vlen_size(kind, vlen);
            }
        }

        None
    }
}

/// Size of variable-length data after the 12-byte type header, per BTF kind.
/// Kind numbers from include/uapi/linux/btf.h:
///   0=UNK 1=INT 2=PTR 3=ARRAY 4=STRUCT 5=UNION 6=ENUM 7=FWD
///   8=TYPEDEF 9=VOLATILE 10=CONST 11=RESTRICT 12=FUNC 13=FUNC_PROTO
///   14=VAR 15=DATASEC 16=FLOAT 17=DECL_TAG 18=TYPE_TAG 19=ENUM64
fn vlen_size(kind: u32, vlen: usize) -> usize {
    match kind {
        1 => 4,                     // INT: 4-byte encoding
        3 => 12,                    // ARRAY: fixed 12-byte btf_array descriptor
        5 => vlen * 12,             // UNION: btf_member entries (same as STRUCT)
        6 => vlen * 8,              // ENUM: 8 bytes per entry (name_off + val)
        13 => vlen * 8,             // FUNC_PROTO: 8 bytes per btf_param (name_off + type)
        14 => 4,                    // VAR: 4-byte linkage
        15 => vlen * 12,            // DATASEC: 12 bytes per btf_var_secinfo
        17 => 4,                    // DECL_TAG: 4-byte component_idx
        19 => vlen * 12,            // ENUM64: 12 bytes per entry
        _ => 0,                     // PTR(2), STRUCT(4) handled separately, FWD(7),
                                    // TYPEDEF(8), VOLATILE(9), CONST(10), RESTRICT(11),
                                    // FUNC(12), FLOAT(16), TYPE_TAG(18): no extra data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_btf() {
        let path = Path::new("/sys/kernel/btf/vmlinux");
        if !path.exists() {
            return; // skip on non-Linux / no BTF
        }
        let btf = BtfData::from_sys_fs().unwrap();

        // task_struct.cgroups should exist; exact offset is kernel-config dependent
        let offset = btf.struct_field_offset("task_struct", "cgroups");
        assert!(offset.is_some(), "task_struct.cgroups not found in BTF");
    }

    #[test]
    fn known_offsets_resolve() {
        let path = Path::new("/sys/kernel/btf/vmlinux");
        if !path.exists() {
            return;
        }
        let btf = BtfData::from_sys_fs().unwrap();

        // Verify all OFFSET_DEFS from ebpf.rs resolve to something.
        let checks = [
            ("task_struct", "cgroups"),
            ("css_set", "dfl_cgrp"),
            ("cgroup", "kn"),
            ("kernfs_node", "id"),
            ("file", "f_inode"),
            ("inode", "i_ino"),
            ("linux_binprm", "file"),
        ];

        for (struct_name, field_name) in checks {
            let offset = btf.struct_field_offset(struct_name, field_name);
            assert!(
                offset.is_some(),
                "{struct_name}.{field_name} not found in BTF"
            );
        }
    }
}
