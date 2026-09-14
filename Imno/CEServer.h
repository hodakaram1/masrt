#pragma once

// =====================================================================
//  CEServer bridge
//
//  Makes Imno speak the Cheat Engine "CEServer" network protocol so that
//  a real Cheat Engine instance can connect over TCP and use Imno as its
//  memory backend. All process-memory operations are served through the
//  DBK64 driver (with a user-mode fallback when the driver is not loaded),
//  so Cheat Engine can read/write protected processes and 32-bit targets.
//
//  The protocol is byte-identical to Cheat Engine's `networkInterface.pas`
//  (CESERVERVERSION 6, version string "CHEATENGINE Network 2.3").
// =====================================================================

#include <string>
#include <vector>

// Start the server on the given TCP port (default 52736, CE's default).
// Runs on background threads. Returns false if it cannot bind/listen.
bool CEServerStart(int port);
void CEServerStop();
bool CEServerIsRunning();
int  CEServerPort();
int  CEServerClientCount();

// Thread-safe snapshot of the recent server log (oldest -> newest).
void CEServerGetLog(std::vector<std::string>& out);
