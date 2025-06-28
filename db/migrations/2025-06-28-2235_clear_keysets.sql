-- tinkrotate had a backwards-incompatible change in the keyset metadata, so clear what might be in the DB.
DELETE FROM tink_keysets;
