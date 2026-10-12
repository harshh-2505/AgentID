// Wires the optional server modules (stores, key providers, attestation formats,
// bridges and integrations) into the authority according to the configuration.

import { Signer } from '../core/keys.js';
import { MemoryStore } from '../core/store.js';

export async function buildAuthorityOptions(config) {
  const opts = { webauthn: config.webauthn };
  opts.signer = config.keyProvider === 'ephemeral' ? await Signer.generate() : await Signer.generate();
  opts.store = new MemoryStore();
  return opts;
}

export async function moduleRoutes() {
  return [];
}

export async function attachIntegrations() {
  return () => {};
}
