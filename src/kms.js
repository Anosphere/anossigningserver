/**
 * The one call to Google Cloud KMS: asymmetricSign on a key version. Used
 * by the kms key store only (pairs.js).
 *
 * The client comes from @google-cloud/kms, as in keyholdersoftware's
 * src/kms/gcp.js: imported and made on the first call, so the local key
 * store never loads the package. It signs in as the machine's own service
 * account; there is no key file. That account holds roles/cloudkms.signer
 * on the key ring and nothing else, so this server can ask for a signature
 * and can never read, make or destroy a key.
 */

let client = null;

/**
 * The client, made once. Kept as a promise: the two halves of a pair are
 * asked at the same moment, and the first signature must not make two
 * clients.
 */
function kmsClient() {
  if (client === null) {
    client = import('@google-cloud/kms').then(
      ({ KeyManagementServiceClient }) => new KeyManagementServiceClient(),
    );
  }
  return client;
}

/**
 * Asks Google for a signature by the key version `versionName`, its full
 * resource name (projects/.../cryptoKeyVersions/<number>). Either
 * { digest }, the SHA-256 of the message, which is what a P-256 key signs,
 * or { data }, the message itself, which is what an ML-DSA-87 key signs;
 * Google takes one or the other, never both. Resolves with the signature
 * as Google gives it: DER for a P-256 key, the 4627 bytes for an ML-DSA-87
 * key. Rejects with Google's error.
 */
export async function ask(versionName, { digest, data }) {
  const request = digest === undefined
    ? { name: versionName, data }
    : { name: versionName, digest: { sha256: digest } };
  const [result] = await (await kmsClient()).asymmetricSign(request);
  return Buffer.from(result.signature);
}
