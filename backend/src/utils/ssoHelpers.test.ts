import { describe, expect, it } from 'vitest';
import { deriveSsoUsername, selectRolesForGroups } from './ssoHelpers.js';

describe('deriveSsoUsername', () => {
  it('uses preferred_username when present and truncates to 12 chars', () => {
    expect(deriveSsoUsername({ preferredUsername: 'alice.smith.longname' })).toBe('alice.smith.');
  });

  it('falls back to nickname, then the email local-part, then a generic name', () => {
    expect(deriveSsoUsername({ nickname: 'bobby', email: undefined })).toBe('bobby');
    expect(deriveSsoUsername({ email: 'bob.smith@example.com' })).toBe('bob.smith');
    expect(deriveSsoUsername({})).toBe('user');
  });

  it('sanitizes whitespace into dashes', () => {
    expect(deriveSsoUsername({ preferredUsername: '  Jane   Doe  ' })).toBe('Jane-Doe');
  });

  it('never returns an empty name', () => {
    expect(deriveSsoUsername({ preferredUsername: '   ' })).toBe('user');
  });
});

describe('selectRolesForGroups', () => {
  const roles = [
    { id: 1, ssoGroups: ['admins'] },
    { id: 2, ssoGroups: [] },
    { id: 3, ssoGroups: ['viewers', 'editors'] },
  ];

  it('selects only roles whose ssoGroups intersect the user groups', () => {
    expect(selectRolesForGroups(['editors', 'other'], roles)).toEqual([roles[2]]);
  });

  it('returns nothing without matching groups or unmapped roles', () => {
    expect(selectRolesForGroups([], roles)).toEqual([]);
    expect(selectRolesForGroups(['nobody'], roles)).toEqual([]);
  });
});
