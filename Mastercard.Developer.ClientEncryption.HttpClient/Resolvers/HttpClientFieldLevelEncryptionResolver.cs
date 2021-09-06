using Mastercard.Developer.ClientEncryption.Core.Encryption;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Mastercard.Developer.ClientEncryption.HttpClient.Resolvers
{
    public class HttpClientFieldLevelEncryptionResolver
    {
        private const string MediaType = "application/json";

        private readonly FieldLevelEncryptionConfig _config;

        public HttpClientFieldLevelEncryptionResolver(FieldLevelEncryptionConfig config)
        {
            _config = config;
        }

        public StringContent BuildEncryptedPayload(string payload)
        {
            try
            {
                // Check request actually has a payload
                if (string.IsNullOrEmpty(payload))
                {
                    // Nothing to encrypt
                    return null;
                }

                // Encrypt fields & update headers
                var encryptedPayload = string.Empty;
                StringContent stringContent;
                if (_config.UseHttpHeaders())
                {
                    // Generate encryption params and add them as HTTP headers
                    var parameters = FieldLevelEncryptionParams.Generate(_config);
                    encryptedPayload = FieldLevelEncryption.EncryptPayload(payload.ToString(), _config, parameters);
                    stringContent = new StringContent(encryptedPayload, Encoding.UTF8, MediaType);

                    stringContent.Headers.Add(_config.IvHeaderName, parameters.IvValue);
                    stringContent.Headers.Add(_config.EncryptedKeyHeaderName, parameters.EncryptedKeyValue);
                    stringContent.Headers.Add(_config.EncryptionCertificateFingerprintHeaderName, _config.EncryptionCertificateFingerprint);
                    stringContent.Headers.Add(_config.EncryptionKeyFingerprintHeaderName, _config.EncryptionKeyFingerprint);
                    stringContent.Headers.Add(_config.OaepPaddingDigestAlgorithmHeaderName, parameters.OaepPaddingDigestAlgorithmValue);
                }
                else
                {
                    // Encryption params will be stored in the payload
                    encryptedPayload = FieldLevelEncryption.EncryptPayload(payload.ToString(), _config);
                    stringContent = new StringContent(encryptedPayload, Encoding.UTF8, MediaType);
                }
                return stringContent;

            }
            catch (EncryptionException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to intercept and encrypt request!", e);
            }
        }

        public async Task<string> ReadAsDecryptedJsonPayload(HttpContent content)
        {
            try
            {
                // Read response payload
                var encryptedPayload = await content.ReadAsStringAsync();

                if (string.IsNullOrEmpty(encryptedPayload))
                {
                    // Nothing to decrypt
                    return string.Empty;
                }

                // Decrypt fields & update headers
                string decryptedPayload = string.Empty;
                if (_config.UseHttpHeaders())
                {
                    // Read encryption params from HTTP headers and delete headers
                    var ivValue = ReadAndRemoveHeader(content.Headers, _config.IvHeaderName);
                    var encryptedKeyValue = ReadAndRemoveHeader(content.Headers, _config.EncryptedKeyHeaderName);
                    var oaepPaddingDigestAlgorithmValue = ReadAndRemoveHeader(content.Headers, _config.OaepPaddingDigestAlgorithmHeaderName);
                    ReadAndRemoveHeader(content.Headers, _config.EncryptionCertificateFingerprintHeaderName);
                    ReadAndRemoveHeader(content.Headers, _config.EncryptionKeyFingerprintHeaderName);
                    var parameters = new FieldLevelEncryptionParams(_config, ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue);
                    decryptedPayload = FieldLevelEncryption.DecryptPayload(encryptedPayload, _config, parameters);
                }
                else
                {
                    // Encryption params are stored in the payload
                    decryptedPayload = FieldLevelEncryption.DecryptPayload(encryptedPayload, _config);
                }

                return decryptedPayload;
            }
            catch (EncryptionException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new EncryptionException("Failed to intercept and decrypt response!", e);
            }
        }

        private string ReadAndRemoveHeader(HttpHeaders headers, string headerName)
        {
            var headerValue = headers.GetValues(headerName).FirstOrDefault();
            headers.Remove(headerName);
            return headerValue;
        }
    }
}
