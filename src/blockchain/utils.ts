/** Coerce a hex digest (with or without 0x) into a valid bytes32; zero-filled when absent/invalid. */
export function normalizeBytes32(value?: string | null): string {
  const hex = (value || '').replace(/^0x/i, '');
  return /^[0-9a-fA-F]{64}$/.test(hex) ? `0x${hex}` : `0x${'0'.repeat(64)}`;
}
