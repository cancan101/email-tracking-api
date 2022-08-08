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
  const iCloudEgressData = await getICloudEgressDataRaw();
  if (iCloudEgressData === null) {
    return null;
  }
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

export async function getICloudEgressEntry(
  clientIp: string
): Promise<ICloudEgressDatum | null> {
  const iCloudEgressData = await getICloudEgressData();
  if (iCloudEgressData === null) {
    return null;
  }
  const clientIpAddress = IPCIDR.createAddress(clientIp);
  const iCloudEgressEntry = iCloudEgressData.find((entry) =>
    clientIpAddress.isInSubnet(entry.cidr)
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
          respJson
        )}`
      )
    );
  }
  return clientIpGeo;
}

async function lookupIpApi(clientIp: string): Promise<ClientIpGeo | null> {
  let clientIpGeo: ClientIpGeo | null = null;
  const resp = await fetchWithTimeout(
    `http://ip-api.com/json/${clientIp}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting`
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

    if (isGoogleLlc) {
      clientIpGeo.rule = "connectionIspGoogleLlc";
      clientIpGeo.emailProvider = EMAIL_PROVIDER_GMAIL;
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
      //   Uncomment this once we resolve the RAM issue:
      //   const iCloudEgressEntry = await getICloudEgressEntry(clientIp);
      //   if (iCloudEgressEntry !== null) {
      //     clientIpGeo.rule = "connectionIspCloudflareInc-icloud";
      //     clientIpGeo.emailProvider = EMAIL_PROVIDER_APPLE_MAIL;
      //     clientIpGeo.data = {
      //       city: iCloudEgressEntry.cityName,
      //       countryCode: iCloudEgressEntry.countryCode,
      //       regionCode: iCloudEgressEntry.regionCode,
      //     };
      //   }
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
          respJson
        )}`
      )
    );
  }
  return clientIpGeo;
}

export async function getClientIpGeo(
  clientIp: string,
  userAgent: string | undefined
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

  const isProxied =
    isProxiedGoogle || isProxiedYahoo || isProxiedFront || isProxiedSuperhuman;

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
    }

    clientIpGeo = { source: "userAgent", emailProvider };
  } else {
    try {
      clientIpGeo = await lookupIpApi(clientIp);
      const clientIpGeoSecondary = await lookupIpwhois(clientIp);
      if (clientIpGeo === null) {
        clientIpGeo = clientIpGeoSecondary;
      } else {
        clientIpGeo.secondary = clientIpGeoSecondary ?? undefined;
      }
    } catch (error) {
      Sentry.captureException(error);
    }
  }
  return clientIpGeo;
}
