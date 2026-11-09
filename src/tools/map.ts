/**
 * Geospatial-related MCP tools for Shodan
 * Map search functionality
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

export const MAP_SEARCH_TOOL: Tool = {
  name: 'map_search',
  description: `Search for hosts within a geospatial bounding box.

Uses Shodan's 'geo:' search filter, so it returns the total count of matching
hosts plus a sample of them (each with its geolocation data).

Define a bounding box by specifying any two opposite corners; they are
normalized to the correct order automatically:
- lat1, lon1: one corner
- lat2, lon2: the opposite corner

Note: Shodan's geolocation is coarse (often city-level), so counts for small
boxes can be larger than expected.

Example: Search for hosts in New York City area:
  lat1: 40.9176 (north), lon1: -74.2591 (west)
  lat2: 40.4774 (south), lon2: -73.7004 (east)`,
  inputSchema: z.object({
    lat1: z.number()
      .min(-90)
      .max(90)
      .describe('Latitude of the north-west corner (or south if lat2 > lat1)'),
    lon1: z.number()
      .min(-180)
      .max(180)
      .describe('Longitude of the north-west corner'),
    lat2: z.number()
      .min(-90)
      .max(90)
      .describe('Latitude of the south-east corner (or north if lat2 > lat1)'),
    lon2: z.number()
      .min(-180)
      .max(180)
      .describe('Longitude of the south-east corner'),
    limit: z.number()
      .min(1)
      .max(1000)
      .default(100)
      .describe('Maximum number of results to return (1-1000)'),
  }),
};

export async function mapSearch(
  client: ShodanClient,
  args: { lat1: number; lon1: number; lat2: number; lon2: number; limit: number }
): Promise<{ content: unknown[] }> {
  const data = await client.mapSearch(args.lat1, args.lon1, args.lat2, args.lon2, args.limit);
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}
