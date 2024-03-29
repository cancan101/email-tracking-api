import * as Sentry from "@sentry/node";
import IPCIDR from "ip-cidr";

import { fetchWithTimeout } from "./utils";
import type { ClientIpGeo } from "./types";

// -------------------------------------------------

const ICLOUD_EGRESS_IP_RANGES =
  "https://mask-api.icloud.com/egress-ip-ranges.csv";

// -------------------------------------------------

const EMAIL_PROVIDER_GMAIL = "Gmail";
const EMAIL_PROVIDER_YAHOO = "Yahoo";
const EMAIL_PROVIDER_FRONT_APP = "FrontApp";
const EMAIL_PROVIDER_APPLE_MAIL = "Apple Mail";
const EMAIL_PROVIDER_SUPERHUMAN = "Superhuman";
const EMAIL_PROVIDER_OUTLOOK365 = "Outlook365";

// -------------------------------------------------

type ICloudEgressDatum = {
  cidr: IPCIDR.Address;
  countryCode: string;
  regionCode: string;
  cityName: string;
};

let iCloudEgressDataCache: ICloudEgressDatum[] | undefined = undefined;

async function getICloudEgressData(): Promise<ICloudEgressDatum[] | null> {
  if (iCloudEgressDataCache !== undefined) {
    return iCloudEgressDataCache;
  }

  console.log("Loading iCloud records from Apple");

  let iCloudEgressData: ICloudEgressDatum[] | null = null;
  try {
    iCloudEgressData = await getICloudEgressDataRaw2();
  } catch (error) {
    // getICloudEgressDataRaw2 raises AbortError rather than TimeoutError,
    // perhaps due to the streaming.
    if (error instanceof DOMException && error.name === "AbortError") {
      console.error("getICloudEgressDataRaw2 call timed-out");
    } else {
      console.error("getICloudEgressDataRaw2 call failed");
      Sentry.captureException(error);
    }
  }

  if (iCloudEgressData === null) {
    console.error("Failed to load iCloud records from Apple");
    return null;
  }
  console.log(`${iCloudEgressData.length} records loaded from Apple`);
  iCloudEgressDataCache = iCloudEgressData;
  return iCloudEgressData;
}

function parseLine(line: string): ICloudEgressDatum {
  const l = line.split(",");

  return {
    cidr: new IPCIDR(l[0]).address,
    countryCode: l[1],
    regionCode: l[2].split("-")[1],
    cityName: l[3],
  };
}

async function getICloudEgressDataRaw(): Promise<ICloudEgressDatum[] | null> {
  const response = await fetchWithTimeout(ICLOUD_EGRESS_IP_RANGES);
  if (!response.ok) {
    return null;
  }
  const responseText = await response.text();

  const lines = responseText.split("\n");

  const iCloudEgressData = lines.map(parseLine);
  return iCloudEgressData;
}

async function getICloudEgressDataRaw2(): Promise<ICloudEgressDatum[] | null> {
  const response = await fetchWithTimeout(ICLOUD_EGRESS_IP_RANGES, {
    timeout: 25000,
  });
  if (!response.ok) {
    return null;
  }
  if (!response.body) {
    return null;
  }

  const records: ICloudEgressDatum[] = [];
  const saver = new WritableStream<string>({
    write(data, controller) {
      records.push(parseLine(data));
    },
  });

  const lineDecoder = new TransformStream<string, string>({
    start(controller) {
      this.partialChunk = "";
    },
    transform(chunk, controller) {
      const normalisedData = this.partialChunk + chunk;
      const chunks = normalisedData.split("\n");
      this.partialChunk = chunks.pop()!;
      for (const chunk of chunks) {
        controller.enqueue(chunk);
      }
    },
    flush(controller) {
      controller.enqueue(this.partialChunk);
      this.partialChunk = "";
    },
  } as Transformer<string, string> & { partialChunk: string });

  await response.body
    .pipeThrough(new TextDecoderStream())
    .pipeThrough(lineDecoder)
    .pipeTo(saver);

  return records;
}

export async function getICloudEgressEntry(
  clientIp: string,
): Promise<ICloudEgressDatum | null> {
  const iCloudEgressData = await getICloudEgressData();
  if (iCloudEgressData === null) {
    return null;
  }
  const clientIpAddress = IPCIDR.createAddress(clientIp);
  const iCloudEgressEntry = iCloudEgressData.find((entry) =>
    clientIpAddress.isInSubnet(entry.cidr),
  );
  return iCloudEgressEntry ?? null;
}

async function lookupIpwhois(clientIp: string): Promise<ClientIpGeo | null> {
  let clientIpGeo: ClientIpGeo | null = null;
  const resp = await fetchWithTimeout(`http://ipwho.is/${clientIp}`);
  clientIpGeo = { source: "ipwhois" };
  if (resp.ok) {
    const clientIpGeoData = await resp.json();

    clientIpGeo.dataRaw = clientIpGeoData;

    // e.g. rate limited
    if (!clientIpGeoData.success) {
      return clientIpGeo;
    }

    const isp = clientIpGeoData?.connection?.isp;

    const isGoogleLlc = isp === "Google LLC";
    // https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/
    const isCloudflareInc = isp === "Cloudflare, Inc.";

    if (isGoogleLlc) {
      clientIpGeo.rule = "connectionIspGoogleLlc";
      clientIpGeo.emailProvider = EMAIL_PROVIDER_GMAIL;
    } else if (isCloudflareInc) {
      clientIpGeo.rule = "connectionIspCloudflareInc";
    } else {
      clientIpGeo.data = {
        city: clientIpGeoData.city as string,
        region: clientIpGeoData.region as string,
        regionCode: clientIpGeoData.region_code as string,
        country: clientIpGeoData.country as string,
        countryCode: clientIpGeoData.country_code as string,
      };
    }
  } else {
    const respJson = await resp.json();
    Sentry.captureException(
      new Error(
        `Unable to fetch IP geo data ${resp.status}: ${JSON.stringify(
          respJson,
        )}`,
      ),
    );
  }
  return clientIpGeo;
}

async function lookupIpApi(clientIp: string): Promise<ClientIpGeo | null> {
  let clientIpGeo: ClientIpGeo | null = null;
  const resp = await fetchWithTimeout(
    `http://ip-api.com/json/${clientIp}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting`,
  );
  clientIpGeo = { source: "ip-api" };
  if (resp.ok) {
    const clientIpGeoData = await resp.json();

    clientIpGeo.dataRaw = clientIpGeoData;

    if (clientIpGeoData.status !== "success") {
      return clientIpGeo;
    }

    const isp = clientIpGeoData?.isp;

    const isGoogleLlc = isp === "Google LLC";
    // https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/
    const isCloudflareInc = isp === "Cloudflare, Inc.";

    const org = clientIpGeoData?.org;
    const isICloudPrivateRelay = org === "iCloud Private Relay";

    // asname: MICROSOFT-CORP-MSN-AS-BLOCK
    const isMicrosoftCorpMsn =
      clientIpGeoData?.as === "AS8075 Microsoft Corporation";

    if (isGoogleLlc) {
      clientIpGeo.rule = "connectionIspGoogleLlc";
      clientIpGeo.emailProvider = EMAIL_PROVIDER_GMAIL;
    } else if (isMicrosoftCorpMsn) {
      clientIpGeo.rule = "asMicrosoftMsn";
      clientIpGeo.emailProvider = EMAIL_PROVIDER_OUTLOOK365;
    } else if (isICloudPrivateRelay) {
      clientIpGeo.rule = "orgICloudPrivateRelay";
      clientIpGeo.emailProvider = EMAIL_PROVIDER_APPLE_MAIL;
      // The data should be reliable here
      clientIpGeo.data = {
        //TODO: factor this out as a helper:
        city: clientIpGeoData.city as string,
        region: clientIpGeoData.regionName as string,
        regionCode: clientIpGeoData.region as string,
        country: clientIpGeoData.country as string,
        countryCode: clientIpGeoData.countryCode as string,
      };
    } else if (isCloudflareInc) {
      clientIpGeo.rule = "connectionIspCloudflareInc";
      const iCloudEgressEntry = await getICloudEgressEntry(clientIp);
      if (iCloudEgressEntry !== null) {
        clientIpGeo.rule = "connectionIspCloudflareInc-icloud";
        clientIpGeo.emailProvider = EMAIL_PROVIDER_APPLE_MAIL;
        clientIpGeo.data = {
          city: iCloudEgressEntry.cityName,
          countryCode: iCloudEgressEntry.countryCode,
          regionCode: iCloudEgressEntry.regionCode,
        };
      }
    } else {
      clientIpGeo.data = {
        city: clientIpGeoData.city as string,
        region: clientIpGeoData.regionName as string,
        regionCode: clientIpGeoData.region as string,
        country: clientIpGeoData.country as string,
        countryCode: clientIpGeoData.countryCode as string,
        isMobile: clientIpGeoData.mobile as boolean,
      };
    }
  } else {
    const respJson = await resp.json();
    Sentry.captureException(
      new Error(
        `Unable to fetch IP geo data ${resp.status}: ${JSON.stringify(
          respJson,
        )}`,
      ),
    );
  }
  return clientIpGeo;
}

export async function getClientIpGeo(
  clientIp: string,
  userAgent: string | undefined,
): Promise<ClientIpGeo | null> {
  let clientIpGeo: ClientIpGeo | null = null;

  const isProxiedGoogle =
    userAgent !== undefined && userAgent.includes("GoogleImageProxy");

  const isProxiedYahoo =
    userAgent !== undefined && userAgent.includes("YahooMailProxy");

  const isProxiedFront =
    userAgent !== undefined && userAgent.includes("FrontApp.com ImageProxy");

  const isProxiedSuperhuman =
    userAgent !== undefined && userAgent === "Superhuman";

  const isProxiedOutlook365 =
    userAgent !== undefined &&
    userAgent ===
      "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35 Safari/537.36";

  const isProxied =
    isProxiedGoogle ||
    isProxiedYahoo ||
    isProxiedFront ||
    isProxiedSuperhuman ||
    isProxiedOutlook365;

  if (isProxied) {
    let emailProvider = undefined;
    if (isProxiedGoogle) {
      emailProvider = EMAIL_PROVIDER_GMAIL;
    } else if (isProxiedYahoo) {
      emailProvider = EMAIL_PROVIDER_YAHOO;
    } else if (isProxiedFront) {
      emailProvider = EMAIL_PROVIDER_FRONT_APP;
    } else if (isProxiedSuperhuman) {
      emailProvider = EMAIL_PROVIDER_SUPERHUMAN;
    } else if (isProxiedOutlook365) {
      emailProvider = EMAIL_PROVIDER_OUTLOOK365;
    }

    clientIpGeo = { source: "userAgent", emailProvider };
  } else {
    try {
      clientIpGeo = await lookupIpApi(clientIp);
    } catch (error) {
      // Prior to Node 19, the name is AbortError
      if (error instanceof DOMException && error.name === "TimeoutError") {
        console.error("lookupIpApi call timed-out");
      } else if (
        error instanceof TypeError &&
        error.cause &&
        (error.cause as any).code === "ECONNRESET"
      ) {
        console.error("lookupIpApi call connection failed");
      } else {
        console.error("lookupIpApi call failed");
        Sentry.captureException(error);
      }
    }

    let clientIpGeoSecondary: ClientIpGeo | null = null;
    try {
      // TODO(cancan101): run these lookups in parallel
      // such that the combined promise does not reject unless both of them reject
      clientIpGeoSecondary = await lookupIpwhois(clientIp);
    } catch (error) {
      // Prior to Node 19, the name is AbortError
      if (error instanceof DOMException && error.name === "TimeoutError") {
        console.error("lookupIpwhois call timed-out");
      } else {
        console.error("lookupIpwhois call failed");
        Sentry.captureException(error);
      }
    }

    if (clientIpGeo === null) {
      clientIpGeo = clientIpGeoSecondary;
    } else {
      clientIpGeo.secondary = clientIpGeoSecondary ?? undefined;
    }
  }
  return clientIpGeo;
}
