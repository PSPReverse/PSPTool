import sys
from psptool import PSPTool, entry
from binascii import hexlify, a2b_hex
import cryptography.hazmat.primitives.serialization as ser

def pubkey_replace(blob, key_id, private_key, new_key_id=None):

    # load new public key numbers
    public_key = private_key.public_key()
    public_key_numbers = public_key.public_numbers()
    public_key_number_len = int(public_key.key_size / 8)
    
    # replace public key numbers
    public_key_entries = blob.pubkeys[key_id]
    for e in public_key_entries:
        assert len(e) in {0x40 + public_key_number_len * 2, 0x40 + public_key_number_len * 3}
        e.pubexp = public_key_numbers.e.to_bytes(public_key_number_len, 'little')
        e.set_bytes(0x40, public_key_number_len, public_key_numbers.e.to_bytes(public_key_number_len, 'little'))
        e.modulus = public_key_numbers.n.to_bytes(public_key_number_len, 'little')
        e.set_bytes(0x40 + public_key_number_len, public_key_number_len, public_key_numbers.n.to_bytes(public_key_number_len, 'little'))

        if new_key_id and key_id != new_key_id:
            # replace key_id's
            e.key_id = new_key_id
            e.set_bytes(0x4, 0x10, a2b_hex(new_key_id))
            if e.certifying_id == key_id:
                e.certifying_id = new_key_id
                e.set_bytes(0x14, 0x10, a2b_hex(new_key_id))
    
    # resign signed keys
    signed_keys = list(pubkey
        for pubkeys in blob.pubkeys.values()
            for pubkey in pubkeys
                if pubkey.certifying_id == key_id
                    and pubkey not in public_key_entries
    )
    for e in signed_keys:
        if new_key_id:
            # replace certifying id
            e.certifying_id = new_key_id
            e.set_bytes(0x14, 0x10, a2b_hex(new_key_id))
        # sign key
        e.sign(private_key)
    
    # resign signed entries
    signed_entries = list(e
        for fet in blob.fets
            for dir in fet.directories
                for e in dir.entries
                    if type(e) == entry.HeaderEntry
                        and e.signature_fingerprint == key_id
    )
    for e in signed_entries:
        if new_key_id:
            # replace signature fingerprint
            e.signature_fingerprint = new_key_id
            e.set_bytes(0x38, 0x10, a2b_hex(new_key_id))
        # sign
        e.sign(private_key)


privkey_file = sys.argv[1]
sev_app_file = sys.argv[2]
orig_rom_file = sys.argv[3]
new_rom_file = sys.argv[4]

print(f'''
    private key:  {privkey_file}
    new sev app:  {sev_app_file}
    original rom: {orig_rom_file}
    output rom:   {new_rom_file}
''')

ans = input("Okay? [y/N]: ")
if not ans or ans[0] not in "yY":
    exit(-1)

# load private key
with open(privkey_file, 'rb') as f:
    privkey_bytes = bytes(f.read())
private_key = ser.load_ssh_private_key(privkey_bytes, password=None)

# load new_sev_app
with open(sev_app_file, 'rb') as f:
    sev_app_bytes = bytes(f.read())

# load original rom
psp = PSPTool.from_file(orig_rom_file, verbose=True)

# helper functions
entries_non_unique = list(e for f in psp.blob.fets for d in f.directories for e in d.entries)
for pubkeys in psp.blob.pubkeys.values():
    entries_non_unique = pubkeys + entries_non_unique
entries = list({ e.get_address() : e for e in entries_non_unique }.values())
entries.sort(key=lambda e: entries_non_unique.index(e))

def first_entry(l):
    return next(filter(l, entries))

def all_entries(l):
    return list(filter(l, entries))


# replace sev_app

sev_app = first_entry(lambda e: e.type == 0x39)
print('Warning: not replacing sev app!')
#if sev_app.body.buffer_size < len(sev_app_bytes):
    #print(f'New sev app is larger than the old one: {hex(sev_app.body.buffer_size)} < {hex(len(sev_app_bytes))}')
    #exit(-1)
#sev_app.body.set_bytes(0, len(sev_app_bytes), sev_app_bytes)

# resign sev_app
sev_app_key_ids = [sev_app.signature_fingerprint]

amd_root_key = first_entry(lambda e: e.type == 0)

while sev_app_key_ids:
    key_id = sev_app_key_ids.pop()
    if key_id == amd_root_key.key_id:
        break
    sev_app_key_ids += list(set(k.certifying_id for k in psp.blob.get_pubkeys(key_id)))
    pubkey_replace(psp.blob, key_id, private_key)

pubkey_replace(psp.blob, key_id, private_key, b'deadbeef'*4)

# save result
psp.to_file(new_rom_file)
