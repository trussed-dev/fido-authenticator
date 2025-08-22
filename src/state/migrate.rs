use littlefs2_core::{path, DirEntry, DynFilesystem, Error, Path, PathBuf};

fn ignore_does_not_exists(error: Error) -> Result<(), Error> {
    if matches!(error, Error::NO_SUCH_ENTRY) {
        return Ok(());
    }
    Err(error)
}

/// Migration function, to be used with trussed-staging's `migrate` management syscall
///
/// `base_path` must be the base of the file directory of the fido app (often `/fido/dat`)
pub fn migrate_no_rp_dir(fs: &dyn DynFilesystem, base_path: &Path) -> Result<(), Error> {
    let rk_dir = base_path.join(path!("rk"));

    fs.read_dir_and_then(&rk_dir, &mut |dir| migrate_rk_dir(fs, &rk_dir, dir))
        .or_else(ignore_does_not_exists)
}

fn migrate_rk_dir(
    fs: &dyn DynFilesystem,
    rk_dir: &Path,
    dir: &mut dyn Iterator<Item = Result<DirEntry, Error>>,
) -> Result<(), Error> {
    for rp in dir.skip(2) {
        let rp = rp?;
        if rp.metadata().is_file() {
            continue;
        }

        migrate_rp_dir(fs, rk_dir, rp.path())?;
    }
    Ok(())
}

fn migrate_rp_dir(fs: &dyn DynFilesystem, rk_dir: &Path, rp_path: &Path) -> Result<(), Error> {
    let rp_id_hex = rp_path.file_name().unwrap().as_str();
    debug_assert_eq!(rp_id_hex.len(), 16);

    fs.read_dir_and_then(rp_path, &mut |rp_dir| {
        for file in rp_dir.skip(2) {
            let file = file?;
            let cred_id_hex = file.file_name().as_str();
            let mut buf = [0; 33];
            buf[0..16].copy_from_slice(rp_id_hex.as_bytes());
            buf[16] = b'.';
            buf[17..].copy_from_slice(cred_id_hex.as_bytes());
            fs.rename(
                file.path(),
                &rk_dir.join(&PathBuf::try_from(buf.as_slice()).unwrap()),
            )?;
        }
        Ok(())
    })?;

    fs.remove_dir(rp_path)?;

    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use admin_app::migrations::test_utils::{test_migration_one, FsValues};

    use super::*;

    const FIDO_DAT_DIR_BEFORE: FsValues = FsValues::Dir(&[
        (path!("persistent-state.cbor"), FsValues::File(137)),
        (
            path!("rk"),
            FsValues::Dir(&[(
                path!("74a6ea9213c99c2f"),
                FsValues::Dir(&[
                    (path!("038dfc6165b78be9"), FsValues::File(128)),
                    (path!("1ecbbfbed8992287"), FsValues::File(122)),
                    (path!("7c24db95312eac56"), FsValues::File(122)),
                    (path!("978cba44dfe39871"), FsValues::File(155)),
                    (path!("ac889a0433749726"), FsValues::File(138)),
                ]),
            )]),
        ),
    ]);

    const FIDO_DAT_DIR_AFTER: FsValues = FsValues::Dir(&[
        (path!("persistent-state.cbor"), FsValues::File(137)),
        (
            path!("rk"),
            FsValues::Dir(&[
                (
                    path!("74a6ea9213c99c2f.038dfc6165b78be9"),
                    FsValues::File(128),
                ),
                (
                    path!("74a6ea9213c99c2f.1ecbbfbed8992287"),
                    FsValues::File(122),
                ),
                (
                    path!("74a6ea9213c99c2f.7c24db95312eac56"),
                    FsValues::File(122),
                ),
                (
                    path!("74a6ea9213c99c2f.978cba44dfe39871"),
                    FsValues::File(155),
                ),
                (
                    path!("74a6ea9213c99c2f.ac889a0433749726"),
                    FsValues::File(138),
                ),
            ]),
        ),
    ]);

    const FIDO_SEC_DIR: FsValues = FsValues::Dir(&[
        (
            path!("069386c3c735689061ac51b8bca9f160"),
            FsValues::File(48),
        ),
        (
            path!("233d86bfc2f196ff7c108cf23a282bd5"),
            FsValues::File(36),
        ),
        (
            path!("2bdef14a0e18d28191162f8c1599d598"),
            FsValues::File(36),
        ),
        (
            path!("3efe6394c20aa8128e27b376e226a58b"),
            FsValues::File(36),
        ),
        (
            path!("4711aa79b4834ef8e551f80e523ba8d2"),
            FsValues::File(36),
        ),
        (
            path!("b43bf8b7897087b7195b8ac53dcb5f11"),
            FsValues::File(36),
        ),
    ]);

    #[test]
    fn migration_no_auth() {
        const TEST_VALUES_BEFORE: FsValues = FsValues::Dir(&[
            (
                path!("fido"),
                FsValues::Dir(&[
                    (path!("dat"), FIDO_DAT_DIR_BEFORE),
                    (path!("sec"), FIDO_SEC_DIR),
                ]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        const TEST_VALUES_AFTER: FsValues = FsValues::Dir(&[
            (
                path!("fido"),
                FsValues::Dir(&[
                    (path!("dat"), FIDO_DAT_DIR_AFTER),
                    (path!("sec"), FIDO_SEC_DIR),
                ]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        test_migration_one(&TEST_VALUES_BEFORE, &TEST_VALUES_AFTER, |fs| {
            migrate_no_rp_dir(fs, path!("fido/dat"))
        });
    }

    #[test]
    fn migration_auth() {
        const AUTH_SECRETS_DIR: (&Path, FsValues) = (
            path!("secrets"),
            FsValues::Dir(&[(
                path!("backend-auth"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[
                        (path!("application_salt"), FsValues::File(16)),
                        (path!("pin.00"), FsValues::File(118)),
                    ]),
                )]),
            )]),
        );

        const BACKEND_DIR: (&Path, FsValues) = (
            path!("backend-auth"),
            FsValues::Dir(&[(
                path!("dat"),
                FsValues::Dir(&[(path!("salt"), FsValues::File(16))]),
            )]),
        );

        const TRUSSED_DIR: (&Path, FsValues) = (
            path!("trussed"),
            FsValues::Dir(&[(
                path!("dat"),
                FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
            )]),
        );

        const TEST_BEFORE: FsValues = FsValues::Dir(&[
            BACKEND_DIR,
            (
                path!("fido"),
                FsValues::Dir(&[
                    (path!("dat"), FIDO_DAT_DIR_BEFORE),
                    (path!("sec"), FIDO_SEC_DIR),
                ]),
            ),
            AUTH_SECRETS_DIR,
            TRUSSED_DIR,
        ]);

        const TEST_AFTER: FsValues = FsValues::Dir(&[
            BACKEND_DIR,
            (
                path!("fido"),
                FsValues::Dir(&[
                    (path!("dat"), FIDO_DAT_DIR_AFTER),
                    (path!("sec"), FIDO_SEC_DIR),
                ]),
            ),
            AUTH_SECRETS_DIR,
            TRUSSED_DIR,
        ]);

        test_migration_one(&TEST_BEFORE, &TEST_AFTER, |fs| {
            migrate_no_rp_dir(fs, path!("fido/dat"))
        });
    }

    #[test]
    fn migration_empty() {
        const TEST_VALUES: FsValues = FsValues::Dir(&[
            (
                path!("fido"),
                FsValues::Dir(&[
                    (path!("dat"), FsValues::Dir(&[])),
                    (path!("sec"), FIDO_SEC_DIR),
                ]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);
        test_migration_one(&TEST_VALUES, &TEST_VALUES, |fs| {
            migrate_no_rp_dir(fs, path!("fido/dat"))
        });
    }
}
