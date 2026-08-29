# Confidential persistent block volumes

Confidential persistent storage is an internal Kata Agent to CDH operation. It
does not use the workload-facing REST API, the optional network gRPC server, or
the free-form `secure_mount` request. Kata Agent calls the typed
`SecureVolumeService` over CDH's guest Unix socket. The extension creates the
socket directory with mode `0700` and the socket with mode `0600`.

## Request and manifest

`ActivateVolume` carries only three values:

- the guest block device identity in `MAJ:MIN` form;
- a content-addressed KBS manifest URI;
- the requested access mode, which is read-write in profile 1.

The manifest URI tag is the lowercase SHA-256 digest of the exact manifest
bytes. Profile 1 uses schema 3:

```json
{
  "schemaVersion": 3,
  "volumeId": "tenant/workload/volume-1",
  "volumeVersion": "generation-1",
  "deviceSizeBytes": 1073741824,
  "access": "readWrite",
  "protection": {
    "type": "luks2-integrity-rw",
    "profileVersion": 1,
    "keyUri": "kbs:///tenant/storage-keys/volume-1-v1",
    "keySha256": "<64 lowercase hexadecimal characters>",
    "luksUuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
  }
}
```

CDH retrieves the manifest and key through its private resource client. The
public resource API must deny the protected key namespace. The key must be 32
uniformly random binary bytes and must match `keySha256` before CDH resolves or
mutates the device.

## Fixed profile 1

The profile is intentionally not caller-configurable:

- LUKS2 with `aes-xts-plain64`, a 512-bit volume key, and 4096-byte sectors;
- a 32-byte binary key file;
- PBKDF2-HMAC-SHA256 with 100,000 forced keyslot iterations;
- journaled `hmac-sha256` dm-integrity;
- a 16 MiB detached header, followed by two 4 KiB authenticated CDH records;
- ext4 with eager inode-table initialization;
- one read-write activation and no resize support.

After formatting or reopening, CDH reads `cryptsetup`'s effective JSON metadata
and rejects any difference in the keyslot, KDF, cipher, sector size, integrity
mode, header layout, or object count. The extension image pins the shipped
`cryptsetup` binary; the guest kernel must provide the matching dm-crypt and
dm-integrity support.

## Activation boundary

Before first use, CDH performs these checks in order:

1. It validates the exact manifest digest, schema, profile, access, device size,
   LUKS UUID, key URI, key length, and key digest.
2. It resolves the declared major/minor, opens that exact block device, and
   keeps the descriptor for the whole activation. Internal reads and writes use
   the held descriptor. Each persistent `cryptsetup` command inherits that
   descriptor and receives `/proc/self/fd/<n>` as its device argument, so a
   devnode swap cannot redirect the command. Path identity checks before and
   after the command remain defense in depth, not the binding mechanism.
3. It serializes activations by major/minor and scans the complete new device.
   A device without authenticated CDH metadata must be entirely zero.
4. It formats the fixed profile, copies the complete detached header into the
   reserved device prefix, and authenticates it with an HMAC derived from the
   volume key and the complete volume binding.
5. It returns only the verified plaintext mapper to Kata Agent, which owns the
   container-scoped mount. The raw block device and recovery key are never
   returned to a workload container.

The authenticated binding covers the volume ID, volume version, exact manifest
digest, profile version, complete LUKS2 header, and lifecycle state. Two state
slots allow recovery from a torn metadata write without guessing whether ext4
may be formatted.

The legacy `sourceType: "persistent"` path fails closed because its free-form
request cannot express this measured binding.

## Integrity and rollback limit

The complete-header HMAC detects header substitution before `cryptsetup` sees
the detached copy. dm-integrity detects corruption or forgery of mutable
ciphertext and keeps data/tag updates crash-consistent.

Neither mechanism proves freshness. A hostile storage provider can replay an
older ciphertext sector together with its previously valid integrity tag,
selectively roll back filesystem state, or create a mixed-epoch filesystem.
Applications that require rollback protection need an external trusted
monotonic state or application-level version protocol.
