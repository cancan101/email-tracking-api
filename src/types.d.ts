type GeoData = {
  city: string;
  region: string;
  regionCode: string;
  country: string;
  countryCode: string;
  isMobile?: boolean;
};

type ClientIpGeo = {
  source: string;
  data?: GeoData;
  dataRaw?: object;
  rule?: string;
  secondary?: ClientIpGeo;
  // TODO: rename this to emailClient, etc
  emailProvider?: string;
};
