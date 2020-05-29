import jwt from "jsonwebtoken";
import { Services } from "../services";
import { InvalidParameterError } from "../errors";
import { Token } from "../services/tokens";
import log from "../log";
import * as uuid from "uuid";

interface Input {
  IdentityId: string;
  Logins: any;
}
interface Credentials {
  AccessKeyId: string;
  Expiration: number;
  SecretKey: string;
  SessionToken: string;
}
interface Output {
  Credentials: Credentials;
  IdentityId: string;
}

export type GetCredentialsForIdentityTarget = (
  body: Input
) => Promise<Output | null>;

export const GetCredentialsForIdentity = ({
  cognitoClient,
}: Services): GetCredentialsForIdentityTarget => async (body) => {
  const keys = Object.keys(body.Logins);
  for (let k = 0; k < keys.length; k++) {
    const key = keys[k];
    if (key.startsWith("cognito-idp.")) {
      const encoded_jwt: string = body.Logins[key] as string;
      const decodedToken = jwt.decode(encoded_jwt) as Token | null;
      if (!decodedToken) {
        log.info("Unable to decode token");
        throw new InvalidParameterError();
      }
      const { sub, aud } = decodedToken;
      if (!sub || !aud) {
        return null;
      }

      const userPool = await cognitoClient.getUserPoolForClientId(aud);
      const user = await userPool.getUserByUsername(sub);
      if (!user) {
        return null;
      }

      const output: Output = {
        IdentityId: body.IdentityId,
        Credentials: {
          AccessKeyId: uuid.v4(),
          Expiration: new Date().getTime() + 30000,
          SecretKey: uuid.v4(),
          SessionToken: uuid.v4(),
        },
      };

      return output;
    }
  }

  return null;
};
