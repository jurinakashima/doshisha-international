import { next } from '@vercel/functions';

// Project-wide HTTP Basic Authentication for the school preview site.
// Only a SHA-256 digest and a non-secret salt are stored in this repository.
// Rotate the random password by replacing both values below.
const USERNAME = 'doshisha-preview';
const PASSWORD_SALT_HEX = '1a560ba088a6043595f7144f4fe987e1';
const PASSWORD_SHA256_HEX = 'caa6fb199b3f72fdd6f8b6e841ace2bf0b2c535b2687f6f63712d61a98d1f123';

function fromHex(hex) {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

function parseBasicAuthorization(value) {
  if (typeof value !== 'string' || value.length > 512) return null;
  const match = /^Basic\s+([A-Za-z0-9+/]+={0,2})$/i.exec(value.trim());
  if (!match) return null;
  try {
    const encoded = atob(match[1]);
    const bytes = Uint8Array.from(encoded, character => character.charCodeAt(0));
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const separator = decoded.indexOf(':');
    if (separator < 1) return null;
    return {
      username: decoded.slice(0, separator),
      password: decoded.slice(separator + 1)
    };
  } catch {
    return null;
  }
}

async function validCredentials(header) {
  const provided = parseBasicAuthorization(header);
  if (!provided || provided.username !== USERNAME) return false;
  const salt = fromHex(PASSWORD_SALT_HEX);
  const passwordBytes = new TextEncoder().encode(provided.password);
  const combined = new Uint8Array(salt.length + passwordBytes.length);
  combined.set(salt);
  combined.set(passwordBytes, salt.length);
  const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', combined));
  const expected = fromHex(PASSWORD_SHA256_HEX);
  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= actual[i] ^ expected[i];
  }
  return difference === 0;
}

export default async function middleware(request) {
  if (await validCredentials(request.headers.get('authorization'))) {
    return next();
  }
  // WWW-Authenticate invokes the browser-native username/password dialog.
  return new Response('Authentication required', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Doshisha International", charset="UTF-8"',
      'Cache-Control': 'private, no-store, max-age=0',
      'Vary': 'Authorization',
      'X-Content-Type-Options': 'nosniff',
      'Content-Type': 'text/plain; charset=utf-8'
    }
  });
}

export const config = { runtime: 'edge' };
