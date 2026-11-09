/**
 * Shodan API Client
 * Handles all API communication with Shodan's REST API.
 *
 * Two hosts are used:
 *   - api.shodan.io   : host/search/count/DNS/domain endpoints
 *   - cvedb.shodan.io : vulnerability (CVE) and CPE endpoints
 *
 * Every endpoint path here is verified against the live API and the official
 * OpenAPI specs (developer.shodan.io/api/openapi.json, cvedb.shodan.io/openapi.json).
 */

const API_BASE_URL = 'https://api.shodan.io';
const CVEDB_BASE_URL = 'https://cvedb.shodan.io';

export interface ShodanClientOptions {
  apiKey: string;
  userAgent?: string;
}

export class ShodanClient {
  private apiKey: string;
  private userAgent: string;

  constructor(options: ShodanClientOptions) {
    this.apiKey = options.apiKey;
    this.userAgent = options.userAgent || 'ShodanMCP/1.0.0';
  }

  private buildUrl(endpoint: string, params: Record<string, string | number>, baseUrl: string): string {
    const url = new URL(`${baseUrl}${endpoint}`);
    url.searchParams.append('key', this.apiKey);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.append(key, String(value));
    }
    return url.toString();
  }

  async request<T>(
    endpoint: string,
    params: Record<string, string | number> = {},
    baseUrl: string = API_BASE_URL
  ): Promise<T> {
    const url = this.buildUrl(endpoint, params, baseUrl);

    const response = await fetch(url, {
      headers: {
        'User-Agent': this.userAgent,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      let errorMessage = `Shodan API error: ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json() as { error?: string; detail?: unknown };
        if (typeof errorData.error === 'string') {
          errorMessage = errorData.error;
        } else if (errorData.detail !== undefined) {
          // cvedb returns FastAPI-style `detail` errors
          errorMessage =
            typeof errorData.detail === 'string'
              ? errorData.detail
              : JSON.stringify(errorData.detail);
        }
      } catch {
        // Use default error message
      }
      throw new Error(errorMessage);
    }

    return response.json() as Promise<T>;
  }

  // Host endpoint methods

  /**
   * Get detailed information about a single host.
   */
  async hostLookup(ip: string): Promise<HostData> {
    return this.request(`/shodan/host/${ip}`);
  }

  /**
   * Get detailed information about multiple hosts (up to 100) in one request.
   * Requires a Corporate or Enterprise Shodan plan.
   */
  async hostBatchLookup(hosts: string[]): Promise<BatchHostData> {
    return this.request(`/shodan/host/${hosts.join(',')}`);
  }

  // Search endpoint methods

  /**
   * Search for hosts matching a query.
   *
   * Pagination uses `offset` + `limit` (never `page` together with `limit`,
   * which the API rejects). `page` is converted to an offset here so callers
   * can keep using page numbers while still honoring an explicit result limit.
   */
  async search(query: string, page = 1, pageSize = 100): Promise<SearchResults> {
    const offset = (Math.max(1, page) - 1) * pageSize;
    return this.request('/shodan/host/search', {
      query,
      offset,
      limit: pageSize,
    });
  }

  /**
   * Get the total count and optional facet breakdowns for a search query.
   */
  async searchStats(query: string, facets?: string[]): Promise<SearchStats> {
    const params: Record<string, string | number> = { query };
    if (facets && facets.length > 0) {
      params.facets = facets.join(',');
    }
    return this.request('/shodan/host/count', params);
  }

  // Organization / network / domain / ISP endpoint methods
  //
  // The current API has no dedicated org/network/ASN endpoints; these are
  // expressed as search filters (org:, net:, asn:) over the host search.

  /**
   * Find hosts belonging to an organization, via the `org:` search filter.
   */
  async organizationLookup(name: string): Promise<SearchResults> {
    return this.search(`org:"${name}"`, 1, 100);
  }

  /**
   * Find hosts within a CIDR block, via the `net:` search filter.
   */
  async networkLookup(cidr: string): Promise<SearchResults> {
    return this.search(`net:${cidr}`, 1, 100);
  }

  /**
   * Get domain intelligence (associated IPs, tags, subdomains).
   */
  async domainLookup(domain: string): Promise<DomainData> {
    return this.request(`/dns/domain/${encodeURIComponent(domain)}`);
  }

  /**
   * Find hosts for an ASN, via the `asn:` search filter.
   * The API requires the `AS` prefix (e.g. `asn:AS15169`).
   */
  async ispLookup(asn: string): Promise<SearchResults> {
    const normalized = asn.toUpperCase().startsWith('AS') ? asn.toUpperCase() : `AS${asn}`;
    return this.search(`asn:${normalized}`, 1, 100);
  }

  // DNS endpoint methods

  /**
   * Forward DNS lookup (hostname -> IP). Returns a map of hostname to IP(s).
   */
  async dnsResolve(hostname: string): Promise<DNSResolveData> {
    return this.request('/dns/resolve', { hostnames: hostname });
  }

  /**
   * Reverse DNS lookup (IP -> hostname). Returns a map of IP to hostnames.
   */
  async dnsReverse(ip: string): Promise<DNSReverseData> {
    return this.request('/dns/reverse', { ips: ip });
  }

  // Vulnerability endpoint methods (cvedb.shodan.io)

  /**
   * Get details for a single CVE.
   */
  async cveLookup(cveId: string): Promise<CVEData> {
    return this.request(`/cve/${encodeURIComponent(cveId)}`, { format: 'json' }, CVEDB_BASE_URL);
  }

  /**
   * Look up CPE product information for the product referenced by a CPE.
   *
   * The current API has no "CPE by id" endpoint, so we parse the product out
   * of the supplied CPE and return all CPE entries (across versions) that
   * match that product via cvedb `/cpes`.
   */
  async cpeLookup(cpeId: string): Promise<CPEResult> {
    const product = this.extractCpeProduct(cpeId);
    return this.request('/cpes', { product, format: 'json' }, CVEDB_BASE_URL);
  }

  /**
   * Get CVEs affecting a vendor (and optionally a specific product).
   */
  async cvesByCpe(vendor: string, product?: string): Promise<CVEByCPEResult> {
    const params: Record<string, string | number> = { vendor, format: 'json' };
    if (product) {
      params.product = product;
    }
    return this.request('/cves', params, CVEDB_BASE_URL);
  }

  /**
   * Search the CPE database by product name.
   *
   * cvedb `/cpes` filters on `product` (a substring match). The optional
   * `vendor` is passed through for intent but is not currently used to filter
   * server-side. Pagination uses `skip` + `limit`.
   */
  async productSearch(query: string, vendor?: string, page = 1, pageSize = 20): Promise<CPEResult> {
    const skip = (Math.max(1, page) - 1) * pageSize;
    const params: Record<string, string | number> = {
      product: query,
      limit: pageSize,
      skip,
      format: 'json',
    };
    if (vendor) {
      params.vendor = vendor;
    }
    return this.request('/cpes', params, CVEDB_BASE_URL);
  }

  // Map endpoint methods

  /**
   * Search for hosts within a geospatial bounding box, via the `geo:` filter.
   *
   * The API expects corners in canonical order (north lat, west lon, south
   * lat, east lon), so we normalize the two supplied corners with min/max.
   */
  async mapSearch(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number,
    limit = 100
  ): Promise<SearchResults> {
    const northLat = Math.max(lat1, lat2);
    const southLat = Math.min(lat1, lat2);
    const westLon = Math.min(lon1, lon2);
    const eastLon = Math.max(lon1, lon2);
    return this.search(`geo:${northLat},${westLon},${southLat},${eastLon}`, 1, limit);
  }

  /**
   * Extract the product field from a CPE string (WAF `cpe:2.3:...` or URN
   * `cpe:/...`). Returns the best-effort product token for `/cpes` lookups.
   */
  private extractCpeProduct(cpeId: string): string {
    const s = cpeId.trim();
    // cpe:2.3:<part>:<vendor>:<product>[:...]  OR  cpe:/<part>:<vendor>:<product>[:...]
    const m = s.match(/^cpe:(?:2\.3:|\/)([a-z]):([^:]+):(.+)$/i);
    if (m) {
      return m[3].split(':')[0];
    }
    // Fallback for bare "vendor:product" or a plain product name.
    const parts = s.split(':').filter(Boolean);
    if (parts.length >= 2) {
      return parts[1];
    }
    return parts[0] ?? s;
  }
}

// TypeScript interfaces for Shodan API responses

export interface HostData {
  ip_str?: string;
  ip?: string;
  asn?: string;
  org?: string;
  isp?: string;
  os?: string;
  hostnames?: string[];
  domains?: string[];
  ports?: number[];
  tags?: string[];
  data?: string;
  city?: string;
  country_code?: string;
  country_name?: string;
  region_code?: string;
  area_code?: string | null;
  latitude?: number;
  longitude?: number;
  last_update?: string;
  [key: string]: unknown;
}

export interface BatchHostData {
  [ip: string]: HostData | string;
}

export interface SearchMatch {
  ip_str?: string;
  ip?: string;
  port?: number;
  asn?: string;
  org?: string;
  isp?: string;
  os?: string;
  hostnames?: string[];
  domains?: string[];
  data?: string;
  transport?: string;
  timestamp?: string;
  location?: {
    country_code?: string;
    country_name?: string;
    city?: string;
    region_code?: string;
    area_code?: string | null;
    latitude?: number;
    longitude?: number;
  };
  [key: string]: unknown;
}

export interface SearchResults {
  total: number;
  matches: SearchMatch[];
  facets?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface SearchStats {
  total: number;
  matches?: unknown[];
  facets?: Record<string, Array<{ count: number; value: string }>>;
  [key: string]: unknown;
}

export interface DomainData {
  domain: string;
  tags?: string[];
  subdomains?: unknown[];
  data?: Record<string, unknown>;
  more?: number | boolean;
  [key: string]: unknown;
}

export interface DNSResolveData {
  [hostname: string]: string | string[];
}

export interface DNSReverseData {
  [ip: string]: string[];
}

export interface CVEData {
  cve_id: string;
  summary?: string;
  cvss?: number | null;
  cvss_v2?: unknown;
  cvss_v3?: unknown;
  cvss_v4?: unknown;
  cvss_version?: string | null;
  epss?: unknown;
  euvd?: unknown;
  ghsa?: unknown;
  kev?: unknown;
  propose_action?: string | null;
  published_time?: string;
  ranking_epss?: number | null;
  ransomware_campaign?: boolean | null;
  references?: unknown[];
  cpes?: string[];
  vendor?: string;
  product?: string;
  version?: string;
  [key: string]: unknown;
}

export interface CPEResult {
  cpes: string[];
  [key: string]: unknown;
}

export interface CVEByCPEResult {
  cves: CVEData[];
  detail?: string;
  [key: string]: unknown;
}
