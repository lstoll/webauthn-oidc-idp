-- We don't use cookie keysets anymore, so delete them
DELETE FROM tink_keysets WHERE id = 'cookie';
