// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The MCP collector: a transparent stdio proxy that pins each server's tool
//! manifest at handshake. See the phase-11a design spec.

pub mod jsonrpc;
pub mod manifest;
pub mod proxy;
pub mod store;
