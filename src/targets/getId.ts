import jwt from "jsonwebtoken";
import { InvalidParameterError } from "../errors";
import log from "../log";
import { Services } from "../services";
import { Token } from "../services/tokens";
import { MFAOption, UserAttribute } from "../services/userPoolClient";

interface Input {
  AccessToken: string;
}

interface Output {
  IdentityId: string;
  MFAOptions?: readonly MFAOption[];
}

export type GetIdTarget = (body: Input) => Promise<Output | null>;

export const GetId = ({ cognitoClient }: Services): GetIdTarget => async (
  body
) => {
  const decodedToken = jwt.decode(body.AccessToken) as Token | null;
  if (!decodedToken) {
    log.info("Unable to decode token");
    throw new InvalidParameterError();
  }

  const { sub, client_id } = decodedToken;
  if (!sub || !client_id) {
    return null;
  }

  const userPool = await cognitoClient.getUserPoolForClientId(client_id);
  const user = await userPool.getUserByUsername(sub);
  if (!user) {
    return null;
  }

  const output: Output = {
    IdentityId: user.IdentityId,
  };

  if (user.MFAOptions) {
    output.MFAOptions = user.MFAOptions;
  }

  return output;
};
