/*
c) Copyright 2024 Akamai Technologies, Inc. Licensed under Apache 2 license.
Purpose: update Akamai-User-Risk header with a score=0 if a certain uuid is found
Akamai Account Protector header going forward to origin looks like this:
Akamai-User-Risk: uuid=86b37525-8047-4a3c-8d7a-23e99901da05;username=testuser@example.com;emailDomain=example.com;ouid=m534264;requestid=19e22e;status=4;score=0;general=aci:0|db:Chrome 85|di:0fc91b5ec42f5a471c16a85e3e388ca57697c1a9|do:Mac OS X 10;risk=;trust=udbp:Chrome 85|udfp:25ba44ec3b391ba4ce5fbbd2979635e254775e7d|udop:Mac OS X 10|ugp:FR|unp:12322|utp:weekday_3;allow=0;action=monitor
*/
import { logger } from "log";

const APR_HEADER_NAME = "Akamai-User-Risk";

const targetUuidList: string[] = [
  "25a35027-980c-4c70-948f-cbea1fac5cf1",
  "e5d06b0d-ef2e-48f7-a4ff-34a3aa64d8b1",
  "f5c63c62-e1bf-4e0c-a5cd-dbc0529eb35d",
];

// convert our list to a set. It automatically makes the list unique and is faster if the list is long.
const targetUuidSet = new Set(targetUuidList.map((uuid) => uuid.toLowerCase()));

export async function onOriginRequest(request: EW.IngressOriginRequest) {
  // get our Akamai Account Protector header, if it exists, null otherwise.
  const aprHeader = request.getHeader(APR_HEADER_NAME)?.[0]?.toLowerCase();

  // a try block so if anything goes wrong just log a message, that's it.
  try {
    if (aprHeader) {
      for (const targetUuid of targetUuidSet) {
        // check if uuid exists in request going to origin
        if (aprHeader.includes(targetUuid)) {
          // if we have a match on uuid, set the score to 0 and set header again and get out of here.
          const newAprHeader = aprHeader.replace(/score=\d+/, "score=0");
          request.setHeader(APR_HEADER_NAME, newAprHeader);

          // no need to go over the whole set if we have a match, just get out of here.
          break;
        }
      }
    }
  } catch (error) {
    logger.error(`Something went wrong: ${error}`);
  }
}
