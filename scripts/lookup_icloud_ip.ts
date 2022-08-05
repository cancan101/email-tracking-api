const { program } = require("commander");
import { getICloudEgressEntry } from "../src/client-info";

program
  .argument("<ipAddress>", "Check if ipAddress is in the iCloud Egress")
  .action((ipAddress: string) => {
    console.log(ipAddress);
    getICloudEgressEntry(ipAddress)
      .catch((e) => {
        throw e;
      })
      .then((entry) => {
        console.log(entry);
      });
  });

program.parse();
