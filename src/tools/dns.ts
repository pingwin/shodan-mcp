/**
 * DNS-related MCP tools for Shodan
 * Forward and reverse DNS lookups
 */

import { z } from 'zod';
import type { ShodanClient } from '../shodan-client.js';

interface Tool {
  name: string;
  description: string;
  inputSchema: z.ZodObject<{
    [key: string]: z.ZodTypeAny;
  }>;
}

export const DNS_RESOLVE_TOOL: Tool = {
  name: 'dns_resolve',
  description: `Perform forward DNS lookup (hostname to IP address).

Converts a hostname to its corresponding IP address using Shodan's DNS database.

Useful for resolving hostnames when you need to look up their IP addresses
for further Shodan queries.`,
  inputSchema: z.object({
    hostname: z.string()
      .min(1)
      .describe('Hostname to resolve to IP address'),
  }),
};

export const DNS_REVERSE_TOOL: Tool = {
  name: 'dns_reverse',
  description: `Perform reverse DNS lookup (IP address to hostname).

Converts an IP address to its corresponding hostname(s) using Shodan's DNS database.

May return multiple hostnames if the IP has multiple reverse DNS records.

Useful for discovering hostnames associated with an IP address.`,
  inputSchema: z.object({
    ip: z.string()
      .ip()
      .describe('IP address to reverse lookup'),
  }),
};

export async function dnsResolve(
  client: ShodanClient,
  args: { hostname: string }
): Promise<{ content: unknown[] }> {
  const data = await client.dnsResolve(args.hostname);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function dnsReverse(
  client: ShodanClient,
  args: { ip: string }
): Promise<{ content: unknown[] }> {
  const data = await client.dnsReverse(args.ip);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}
