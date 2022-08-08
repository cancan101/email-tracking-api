import IPCIDR from "ip-cidr";

const decoderInfo = {
  partialChunk: "",
  transform(
    chunk: string,
    controller: TransformStreamDefaultController<string>
  ) {
    const normalisedData = this.partialChunk + chunk;
    const chunks = normalisedData.split("\n");
    this.partialChunk = chunks.pop()!;
    for (const chunk of chunks) {
      controller.enqueue(chunk);
    }
  },
};
const lineDecoder = new TransformStream<string, string>(decoderInfo);

async function run() {
  const resp = await fetch("https://mask-api.icloud.com/egress-ip-ranges.csv");
  if (!resp.ok) {
    console.log("no ok");
    return;
  }
  if (!resp.body) {
    console.log("no body");
    return;
  }
  console.log("running");
  const records: any[] = [];
  const saver = new WritableStream<string>({
    write(data, controller) {
      const l = data.split(",");
      records.push({
        cidr: new IPCIDR(l[0]).address,
        countryCode: l[1],
        regionCodeWithCountry: l[2],
        cityName: l[3],
      });
    },
  });

  await resp.body
    .pipeThrough(new TextDecoderStream())
    .pipeThrough(lineDecoder)
    .pipeTo(saver);

  return records;
}

run().then((records: undefined | any[]) => {
  console.log("done", records && records.length);
  //   while (true) {}
});
