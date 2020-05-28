import jwt from "jsonwebtoken";
import { InvalidParameterError } from "../errors";
import log from "../log";
import { Services } from "../services";
import { Token } from "../services/tokens";
import { MFAOption, UserAttribute } from "../services/userPoolClient";

interface Input {
  IdentityPoolId: string;
  Logins: Map<string, string>;
}

interface Output {
  IdentityId: string;
  MFAOptions?: readonly MFAOption[];
}

export type GetIdTarget = (body: Input) => Promise<Output | null>;

export const GetId = ({ cognitoClient }: Services): GetIdTarget => async (
  body
) => {
  for (const key in body.Logins.keys()) {
    if (key.startsWith("cognito-idp.")) {
      const encoded_jwt: string = body.Logins.get(key) as string;
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
        IdentityId: user.IdentityId,
      };

      return output;
    }
  }

  return null;
};
