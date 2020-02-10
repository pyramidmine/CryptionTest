using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Validator
{
	class Program
	{
		/// <summary>
		/// 샘플 데이터
		/// </summary>
		static readonly string SAMPLE_TEXT = "배달 문화를 선도하는 만나플러스, (C) Manna Planet 2020";
		static readonly byte[] SAMPLE_ENCODED_DATA = Encoding.UTF8.GetBytes(SAMPLE_TEXT);

		/// <summary>
		/// HMAC
		/// </summary>
		static readonly int HMAC_KEY_SIZE = 64;
		static readonly string CS_HMAC_KEY_FILENAME = "cs.hmac.key";
		static readonly string CS_HMAC_HASH_FILENAME = "cs.hmac.hash";
		static readonly string JAVA_HMAC_KEY_FILENAME = "java.hmac.key";

		/// <summary>
		/// RSA
		/// </summary>
		static readonly string CS_RSA_PRIVATE_KEY_FILENAME = "cs.rsa.private.key";
		static readonly string CS_RSA_PUBLIC_KEY_FILENAME = "cs.rsa.public.key";

		static void Main(string[] args)
		{
			TestHMAC();

			//
			// 개인키 생성 (키 파일이 있으면 기존 키 로드)
			//
			var privateKey = new RSAParameters();
			var privateRsa = new RSACryptoServiceProvider();

			string privateKeyFile = Path.Combine(GetKeyDirectory(), CS_RSA_PRIVATE_KEY_FILENAME);
			if (File.Exists(privateKeyFile))
			{
				privateRsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(privateKeyFile)));
				privateKey = privateRsa.ExportParameters(true);
			}
			else
			{
				privateKey = RSA.Create().ExportParameters(true);
				privateRsa.ImportParameters(privateKey);
				File.WriteAllText(privateKeyFile, Convert.ToBase64String(privateRsa.ExportCspBlob(true)));
			}

			Console.WriteLine($"---------- After Import Private Key ----------");
			Console.WriteLine($"PRIVATE KEY:");
			Console.WriteLine(Convert.ToBase64String(privateRsa.ExportCspBlob(true)));
			Console.WriteLine($"PUBLIC KEY:");
			Console.WriteLine(Convert.ToBase64String(privateRsa.ExportCspBlob(false)));

			//
			// 개인키에 기반해서 공개키 생성 (키 파일이 있으면 기존 키 로드)
			//
			var publicKey = new RSAParameters();
			var publicRsa = new RSACryptoServiceProvider();

			string publicKeyFile = Path.Combine(GetKeyDirectory(), CS_RSA_PUBLIC_KEY_FILENAME);
			if (File.Exists(publicKeyFile))
			{
				publicRsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(publicKeyFile)));
				publicKey = publicRsa.ExportParameters(false);
			}
			else
			{
				publicKey.Modulus = privateKey.Modulus;
				publicKey.Exponent = privateKey.Exponent;
				publicRsa.ImportParameters(publicKey);
				File.WriteAllText(publicKeyFile, Convert.ToBase64String(publicRsa.ExportCspBlob(false)));
			}

			Console.WriteLine($"---------- After Import Public Key ----------");
			Console.WriteLine($"PUBLIC KEY:");
			Console.WriteLine(Convert.ToBase64String(publicRsa.ExportCspBlob(false)));

			//
			// 공개키로 암호화, 개인키로 복호화 하는 일반적인 과정
			// 클라이언트 -> 서버 방향
			//

			// 인코딩
			byte[] encodedData = Encoding.UTF8.GetBytes(SAMPLE_TEXT);

			// 암호화
			byte[] encryptedData = publicRsa.Encrypt(encodedData, false);

			// 복호화
			byte[] decryptedData = privateRsa.Decrypt(encryptedData, false);

			// 디코딩
			string decodedText = Encoding.UTF8.GetString(decryptedData);

			// 결과 출력
			Console.WriteLine("---------- Public Key - Encryption, Private Key - Decryption ----------");
			Console.WriteLine($"Original Text : {SAMPLE_TEXT}");
			Console.WriteLine($"Decrypted Text: {decodedText}");

			//
			// 서버 -> 클라이언트 방향, 즉 암/복호화 방향을 반대로 해서, 개인키로 암호화하고 공개키로 복호화하는 건 허용되지 않음 (MS가 의도적으로 한 것 같음)
			//
			// 그대신 개인키로 사인하고, 공개키로 검증해서 이 데이터가 실제로 키 소유자가 보낸 건지 확인 가능
			// 즉, 데이터와 데이터를 해시한 값을 개인키로 암호화해서 보내면, 받은 쪽에서는 데이터를 해시한 다음, 공개키로 해시한 값을 복호화해서 비교하면 된다
			// 이것을 한큐에 해 주는 게 SignData/VerifyData
			//

			// 개인키로 사인
			byte[] signedData = privateRsa.SignData(encodedData, new SHA256CryptoServiceProvider());

			// 공개키로 검증
			bool verified = publicRsa.VerifyData(encodedData, new SHA256CryptoServiceProvider(), signedData);

			// 결과 출력
			Console.WriteLine("---------- Private Key - SignData, Public Key - VerifyData ----------");
			Console.WriteLine($"Signed Data: {Convert.ToBase64String(signedData)}");
			Console.WriteLine($"Verification: {verified}");

			//
			// 클라이언트 -> 서버 방향에서, 클라이언트를 검증하고 싶을 때는, Encrypt/Decrypt + Sign/Verify 조합을 사용하면 된다
			// 즉, 데이터는 암호화 하고, 클라이언트의 개인키로 사인하고, 서버는 클라이언트의 공개키로 시그니처를 검증하는 식
			// 이때, 해시를 따로 하고 싶으면 SignHash, 함께 하고 싶으면 SignData를 사용하면 됨
			//

			/*

			// 키 파일이 존재하면 키 파일을 읽음
			string currDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			string keyFilePattern = "*.rsa.*.key";
			string[] files = Directory.GetFiles(currDirectory, keyFilePattern);
			List<string> publicKeyFiles = files.Where(file => file.Contains("public")).ToList();
			List<string> privateKeyFiles = files.Where(file => file.Contains("private")).ToList();
			if (0 < publicKeyFiles.Count)
			{
				rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(publicKeyFiles[0])));
			}
			if (0 < privateKeyFiles.Count)
			{
				rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(publicKeyFiles[0])));
			}

			using (var rsa = new RSACryptoServiceProvider())
			{
				string xmlPublicKey = rsa.ToXmlString(false);
				Console.WriteLine("---------- Public Key ----------");
				Console.WriteLine(xmlPublicKey);
				string xmlPrivateKey = rsa.ToXmlString(true);
				Console.WriteLine("---------- Private Key ----------");
				Console.WriteLine(xmlPrivateKey);
				byte[] blobPublicKey = rsa.ExportCspBlob(false);
				Console.WriteLine("---------- Blob Public Key ----------");
				Console.WriteLine(Convert.ToBase64String(blobPublicKey));
				byte[] blobPrivateKey = rsa.ExportCspBlob(true);
				Console.WriteLine("---------- Blob Private Key ----------");
				Console.WriteLine(Convert.ToBase64String(blobPrivateKey));
			}
			*/
		}

		private static void TestHMAC()
		{
			byte[] keyData = new byte[HMAC_KEY_SIZE];

			string keyFile = Path.Combine(GetKeyDirectory(), CS_HMAC_KEY_FILENAME);
			if (File.Exists(keyFile))
			{
				// 키 파일이 존재하면 키 파일 로드
				keyData = Convert.FromBase64String(File.ReadAllText(keyFile));
			}
			else
			{
				// 키 파일이 없으면 키 생성
				using (var rng = new RNGCryptoServiceProvider())
				{
					rng.GetBytes(keyData);
				}
				File.WriteAllText(keyFile, Convert.ToBase64String(keyData));
			}

			// 해쉬
			byte[] hashedData;
			using (var hmac = new HMACSHA256(keyData))
			{
				hashedData = hmac.ComputeHash(SAMPLE_ENCODED_DATA);
				string hashFile = Path.Combine(GetKeyDirectory(), CS_HMAC_HASH_FILENAME);
				File.WriteAllText(hashFile, Convert.ToBase64String(hashedData));
			}

			// 해쉬 검증
			byte[] verifyingKeyData = Convert.FromBase64String(File.ReadAllText(keyFile));
			byte[] verifyingHashedData = null;
			using (var hmac = new HMACSHA256(verifyingKeyData))
			{
				verifyingHashedData = hmac.ComputeHash(SAMPLE_ENCODED_DATA);
			}

			// 결과 출력
			Console.WriteLine("---------- C# HMAC -----------");
			Console.WriteLine($"Original Hash: {Convert.ToBase64String(hashedData)}");
			Console.WriteLine($"Verified Hash: {Convert.ToBase64String(verifyingHashedData)}");

			// 다른 언어 키 파일 읽어서 검증
			string otherKeyFile = Path.Combine(GetKeyDirectory(), JAVA_HMAC_KEY_FILENAME);
			if (File.Exists(otherKeyFile))
			{
				byte[] otherKeyData = Convert.FromBase64String(File.ReadAllText(otherKeyFile));
				using (var hmac = new HMACSHA256(otherKeyData))
				{
					byte[] otherHashedData = hmac.ComputeHash(SAMPLE_ENCODED_DATA);

					// 결과 출력
					Console.WriteLine("---------- Verify Java HMAC ----------");
					Console.WriteLine($"Original Hash: {Convert.ToBase64String(hashedData)}");
					Console.WriteLine($"Verified Hash: {Convert.ToBase64String(otherHashedData)}");
				}
			}
		}

		private static string GetKeyDirectory()
		{
			return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
		}
	}
}
