/**
 * Vulnerability-related MCP tools for Shodan
 * CVE, CPE, and product vulnerability lookups
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

export const CVE_LOOKUP_TOOL: Tool = {
  name: 'cve_lookup',
  description: `Look up details for a specific CVE (Common Vulnerabilities and Exposures).

Returns comprehensive information about a vulnerability including:
- CVE ID and description
- CVSS severity score
- Affected CPEs (products)
- References and links
- Publication date

Use this tool to get detailed information about specific vulnerabilities.

Example CVE format: 'CVE-2017-0144'`,
  inputSchema: z.object({
    cveId: z.string()
      .regex(/^CVE-\d{4}-\d{4,}$/)
      .describe('CVE identifier (e.g., "CVE-2017-0144")'),
  }),
};

export const CPE_LOOKUP_TOOL: Tool = {
  name: 'cpe_lookup',
  description: `Look up CPE (Common Platform Enumeration) product information.

CPE is a standardized naming scheme for information technology systems,
components, and applications.

Provide a CPE identifier; the product is extracted from it and all matching
CPE entries (across versions) are returned from Shodan's CPE database.

Example CPE formats: 'cpe:/a:apache:http_server' or
'cpe:2.3:a:apache:http_server:2.4.0'.`,
  inputSchema: z.object({
    cpeId: z.string()
      .min(1)
      .describe('CPE identifier (e.g., "cpe:/a:apache:http_server" or "cpe:2.3:a:apache:http_server:2.4.0")'),
  }),
};

export const CVES_BY_CPE_TOOL: Tool = {
  name: 'cves_by_cpe',
  description: `Find all CVEs affecting a vendor's product(s).

Returns a list of vulnerabilities (with CVSS, EPSS, KEV status, affected
versions, references, etc.) for a given vendor, optionally narrowed to one
product.

Example: Find all CVEs for Apache HTTP Server (vendor 'apache',
product 'http_server').`,
  inputSchema: z.object({
    vendor: z.string()
      .min(1)
      .describe('Vendor name (e.g., "apache", "microsoft", "cisco")'),
    product: z.string()
      .optional()
      .describe('Product name (optional; when omitted, returns CVEs for all of the vendor\'s products)'),
  }),
};

export const PRODUCT_SEARCH_TOOL: Tool = {
  name: 'product_search',
  description: `Search for products in Shodan's CPE database.

Searches by product name (substring match) and returns matching CPE
identifiers across versions. Useful for finding the correct CPE identifier
for a product.

Note: results are matched on the product term; an optional vendor is accepted
but not used to filter server-side.`,
  inputSchema: z.object({
    query: z.string()
      .min(1)
      .describe('Product name or substring to search for (e.g., "http_server", "libpng")'),
    vendor: z.string()
      .optional()
      .describe('Optional vendor filter (accepted for intent; not used to filter server-side)'),
    limit: z.number()
      .min(1)
      .max(100)
      .default(20)
      .describe('Maximum number of results to return (1-100)'),
    page: z.number()
      .min(1)
      .default(1)
      .describe('Page number for pagination'),
  }),
};

export async function cveLookup(
  client: ShodanClient,
  args: { cveId: string }
): Promise<{ content: unknown[] }> {
  const data = await client.cveLookup(args.cveId);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function cpeLookup(
  client: ShodanClient,
  args: { cpeId: string }
): Promise<{ content: unknown[] }> {
  const data = await client.cpeLookup(args.cpeId);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function cvesByCpe(
  client: ShodanClient,
  args: { vendor: string; product?: string }
): Promise<{ content: unknown[] }> {
  const data = await client.cvesByCpe(args.vendor, args.product);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

export async function productSearch(
  client: ShodanClient,
  args: { query: string; vendor?: string; limit: number; page: number }
): Promise<{ content: unknown[] }> {
  const data = await client.productSearch(args.query, args.vendor, args.page, args.limit);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}
