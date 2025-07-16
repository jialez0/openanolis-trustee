// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs::admin::{error::Error, error::Result};
use std::io;

#[test]
fn test_error_display() {
    let error = Error::NoPublicKeyGiven;
    assert_eq!(
        format!("{}", error),
        "`auth_public_key` is not set in the config file"
    );

    let io_error = io::Error::new(io::ErrorKind::Other, "test error");
    let error = Error::ReadPublicKey(io_error);
    assert_eq!(format!("{}", error), "Read admin public key failed");

    // Test that we can convert from io::Error to Error
    let io_error = io::Error::new(io::ErrorKind::Other, "test error");
    let error: Result<()> = Err(io_error.into());
    assert!(error.is_err());
}