/**
 * Organization-related MCP tools for Shodan
 * Organization, network, domain, and ISP lookups
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

export const ORGANIZATION_LOOKUP_TOOL: Tool = {
  name: 'organization_lookup',
  description: `Look up an organization by name and list its hosts.

Uses Shodan's 'org:' search filter, so it returns the total number of hosts
the organization operates plus a sample of matching hosts (each with ASN,
IP, hostnames, location, etc.).

Use this tool to find how many hosts belong to a specific organization and
see examples of them.`,
  inputSchema: z.object({
    orgName: z.string()
      .min(1)
      .describe('Name of the organization to look up'),
  }),
};

export const NETWORK_LOOKUP_TOOL: Tool = {
  name: 'network_lookup',
  description: `Look up a network by CIDR block and list its hosts.

Uses Shodan's 'net:' search filter, so it returns the total number of hosts
in the network range plus a sample of matching hosts (each with ASN,
organization, IP, hostnames, location, etc.).

Example CIDRs: '8.8.8.0/24', '192.168.1.0/24'.`,
  inputSchema: z.object({
    cidr: z.string()
      .describe('CIDR block to look up (e.g., "192.168.1.0/24")'),
  }),
};

export const DOMAIN_LOOKUP_TOOL: Tool = {
  name: 'domain_lookup',
  description: `Get domain intelligence data.

Returns information about a domain including:
- All IP addresses associated with the domain
- Tags (vulnerabilities, technologies detected)
- Last update timestamp
- ASN and network information

Useful for understanding the attack surface of a domain.`,
  inputSchema: z.object({
    domain: z.string()
      .min(1)
      .describe('Domain name to look up'),
  }),
};

export const ISP_LOOKUP_TOOL: Tool = {
  name: 'isp_lookup',
  description: `Look up an ASN (Autonomous System Number) and list its hosts.

Uses Shodan's 'asn:' search filter, so it returns the total number of hosts
in the ASN plus a sample of matching hosts (each with ISP/organization, IP,
hostnames, location, etc.).

You can provide the ASN with or without the 'AS' prefix (e.g. '15169' or 'AS15169').`,
  inputSchema: z.object({
    asn: z.string()
      .min(1)
      .describe('ASN number to look up (with or without "AS" prefix)'),
  }),
};

export async function organizationLookup(
  client: ShodanClient,
  args: { orgName: string }
): Promise<{ content: unknown[] }> {
  const data = await client.organizationLookup(args.orgName);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function networkLookup(
  client: ShodanClient,
  args: { cidr: string }
): Promise<{ content: unknown[] }> {
  const data = await client.networkLookup(args.cidr);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function domainLookup(
  client: ShodanClient,
  args: { domain: string }
): Promise<{ content: unknown[] }> {
  const data = await client.domainLookup(args.domain);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function ispLookup(
  client: ShodanClient,
  args: { asn: string }
): Promise<{ content: unknown[] }> {
  const data = await client.ispLookup(args.asn);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}
