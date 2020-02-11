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
		static readonly string SAMPLE_FILENAME = "sample.txt";
		static string SAMPLE_TEXT = "배달 문화를 선도하는 만나플러스, (C) Manna Planet 2020";
		static byte[] SAMPLE_ENCODED_DATA = Encoding.UTF8.GetBytes(SAMPLE_TEXT);

		/// <summary>
		/// HMAC
		/// </summary>
		static readonly int HMAC_KEY_SIZE = 64;
		static readonly string CS_HMAC_KEY_FILENAME = "cs.hmac.key";
		static readonly string CS_HMAC_HASH_FILENAME = "cs.hmac.hash";
		static readonly string JAVA_HMAC_KEY_FILENAME = "java.hmac.key";

		/// <summary>
		/// AES
		/// </summary>
		static readonly int AES_KEY_SIZE = 32;
		static readonly int AES_IV_SIZE = 16;
		static readonly int AES_PASSWORD_SIZE = 32;
		static readonly int AES_SALT_SIZE = 32;
		static readonly int AES_ITERATION_COUNT = 1;
		static readonly string CS_AES_EMPTY_IV = "                ";

		class AesFiles
		{
			public string Language { get; set; }
			public string KeyFile { get; set; }
			public string IvFile { get; set; }
			public string EncryptedFile { get; set; }
		}
		static List<AesFiles> aesFiles = new List<AesFiles>()
		{
			new AesFiles { Language = "cs", KeyFile = "cs.aes.key", IvFile = "cs.aes.iv", EncryptedFile = "cs.aes.data" },
			new AesFiles { Language = "java", KeyFile = "java.aes.key", IvFile = "java.aes.iv", EncryptedFile = "java.aes.data" }
		};

		/// <summary>
		/// RSA
		/// </summary>
		static readonly string CS_RSA_PRIVATE_KEY_FILENAME = "cs.rsa.private.key";
		static readonly string CS_RSA_PUBLIC_KEY_FILENAME = "cs.rsa.public.key";

		static void Main(string[] args)
		{
			PrepareSampleData();
			PrepareLanguageData();

			//			TestHMAC();
			TestBasicAES();
			TestAES();

			return;

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

		private static void PrepareLanguageData()
		{
			// AES 파일 준비
			for (int i = 0; i < aesFiles.Count; i++)
			{
				aesFiles[i].KeyFile = Path.Combine(GetKeyDirectory(), aesFiles[i].KeyFile);
				aesFiles[i].IvFile = Path.Combine(GetKeyDirectory(), aesFiles[i].IvFile);
				aesFiles[i].EncryptedFile = Path.Combine(GetKeyDirectory(), aesFiles[i].EncryptedFile);
			}
		}

		private static void PrepareSampleData()
		{
			string sampleFile = Path.Combine(GetKeyDirectory(), SAMPLE_FILENAME);
			if (File.Exists(sampleFile))
			{
				// 샘플 파일이 있으면 로드
				SAMPLE_ENCODED_DATA = Convert.FromBase64String(File.ReadAllText(sampleFile));   // Base64 -> UTF-8
				SAMPLE_TEXT = Encoding.UTF8.GetString(SAMPLE_ENCODED_DATA);						// UTF-8 -> string
			}
			else
			{
				// 샘플 파일이 없으면 생성 및 저장
				File.WriteAllText(sampleFile, Convert.ToBase64String(SAMPLE_ENCODED_DATA));
			}
		}

		private static void TestBasicAES()
		{
			//
			// 키 생성 테스트
			//

			int keySize = 32;
			int passwordSize = 32;
			int saltSize = 32;

			// 키와 솔트를 랜덤하게 생성하기 위해 RNGCryptoServiceProvider 이용
			RNGCryptoServiceProvider rnd = new RNGCryptoServiceProvider();
			byte[] password = new byte[passwordSize];
			byte[] salt = new byte[saltSize];
			rnd.GetBytes(password);
			rnd.GetBytes(salt);
			int iterations = 1;

			// 키와 솔트와 반복횟수를 지정하면 랜덤한 키 데이터를 생성해주는 Rfc2898DeriveBytes 이용
			Rfc2898DeriveBytes keyGen = new Rfc2898DeriveBytes(password, salt, iterations);
			List<byte[]> keyDataList = new List<byte[]>();
			int keyDataCount = 5;
			for (int i = 0; i < keyDataCount; i++)
			{
				// 키 생성
				keyDataList.Add(keyGen.GetBytes(keySize));
			}
			// 생성된 키 출력
			keyDataList.ForEach(keyData => Console.WriteLine($"Key Data: {Convert.ToBase64String(keyData)}"));
		}

		/// <summary>
		/// AES 테스트
		/// <para>
		/// 참고:
		/// 1. 암호화 키와 복호화 키가 다르면 익셉션 발생
		/// 2. 암호화 IV와 복호화 IV가 다르면 익셉션은 발생하지 않지만 제대로 복호화 되지 않음
		/// 3. IV는 NULL이면 안 됨
		/// </para>
		/// </summary>
		private static void TestAES()
		{
			var csFiles = aesFiles[0];

			byte[] keyData = null;
			if (File.Exists(csFiles.KeyFile))
			{
				// 키 파일이 존재하면 키 파일 로드
				keyData = Convert.FromBase64String(File.ReadAllText(csFiles.KeyFile));
			}
			else
			{
				// 키 파일이 없으면 키 생성 및 저장
				keyData = AesCreateKey(AES_KEY_SIZE);
				File.WriteAllText(csFiles.KeyFile, Convert.ToBase64String(keyData));
			}

			byte[] ivData = null;
			if (File.Exists(csFiles.IvFile))
			{
				// IV 파일이 존재하면 IV 파일 로드
				ivData = Convert.FromBase64String(File.ReadAllText(csFiles.IvFile));
			}
			else
			{
				// IV 파일이 없으면 IV 생성 및 저장
				ivData = AesCreateKey(AES_IV_SIZE);
				File.WriteAllText(csFiles.IvFile, Convert.ToBase64String(ivData));
			}

			// 암호화 객체 생성
			RijndaelManaged rm = new RijndaelManaged()
			{
				KeySize = 256,
				BlockSize = 128,
				Mode = CipherMode.CBC,
				Padding = PaddingMode.PKCS7,
				Key = keyData,
				IV = ivData
			};

			// 암호화
			ICryptoTransform encryptor = rm.CreateEncryptor();
			byte[] encryptedData = AesEncrypt(SAMPLE_ENCODED_DATA, encryptor);
			File.WriteAllText(csFiles.EncryptedFile, Convert.ToBase64String(encryptedData));

			// 복호화
			ICryptoTransform decryptor = rm.CreateDecryptor();
			byte[] decryptedData = AesDecrypt(encryptedData, decryptor);

			// 결과 출력
			Console.WriteLine("---------- C# AES ----------");
			Console.WriteLine($"Original Data : {Convert.ToBase64String(SAMPLE_ENCODED_DATA)}");
			Console.WriteLine($"Decrypted Data: {Convert.ToBase64String(decryptedData)}");

			// IV 바꿔서 암호화
			rm.IV = AesCreateKey(AES_IV_SIZE);
			encryptor = rm.CreateEncryptor();
			byte[] encryptedDataWithIvChange = AesEncrypt(SAMPLE_ENCODED_DATA, encryptor);

			// IV 바꿔서 복호화
			decryptor = rm.CreateDecryptor();
			byte[] decryptedDataWithIvChange = AesDecrypt(encryptedDataWithIvChange, decryptor);

			// 결과 출력
			Console.WriteLine("---------- C# AES (IV Change) ----------");
			Console.WriteLine($"Original Data:  {Convert.ToBase64String(SAMPLE_ENCODED_DATA)}");
			Console.WriteLine($"Decrypted Data: {Convert.ToBase64String(decryptedDataWithIvChange)}");
			Console.WriteLine($"Encrypted Data(IV#1): {Convert.ToBase64String(encryptedData)}");
			Console.WriteLine($"Encrypted Data(IV#2): {Convert.ToBase64String(encryptedDataWithIvChange)}");

			// IV #1 암호화
			rm.IV = AesCreateKey(AES_IV_SIZE);
			encryptor = rm.CreateEncryptor();
			byte[] encryptedDataWithIv1 = AesEncrypt(SAMPLE_ENCODED_DATA, encryptor);

			// IV #2 복호화
			rm.IV = AesCreateKey(AES_IV_SIZE);
			decryptor = rm.CreateDecryptor();
			byte[] decryptedDataWithIv2 = AesDecrypt(encryptedDataWithIv1, decryptor);

			// 결과 출력 
			Console.WriteLine("---------- C# AES (IV Cross) ----------");
			Console.WriteLine($"Original Data:  {Convert.ToBase64String(SAMPLE_ENCODED_DATA)}");
			Console.WriteLine($"Decrypted Data: {Convert.ToBase64String(decryptedDataWithIv2)}");

			// 엉뚱한 키로 복호화 시도
			Console.WriteLine("---------- C# AES (Fake Key) ----------");
			rm.Key = AesCreateKey(AES_KEY_SIZE);
			rm.IV = ivData;
			decryptor = rm.CreateDecryptor();
			byte[] decryptedDataWithFakeKey = new byte[] { };
			try
			{
				decryptedDataWithFakeKey = AesDecrypt(encryptedData, decryptor);
			}
			catch (Exception e)
			{
				Console.WriteLine($"EXCEPTION: {e.GetType().Name}, {e.Message}");
			}

			// 결과 출력
			Console.WriteLine($"Original Data:  {Convert.ToBase64String(SAMPLE_ENCODED_DATA)}");
			Console.WriteLine($"Decrypted Data: {Convert.ToBase64String(decryptedDataWithFakeKey)}");

			// 빈 IV 이용해서 암호화
			Console.WriteLine("---------- C# AES (Without Iv) ----------");
			rm.IV = Encoding.UTF8.GetBytes(CS_AES_EMPTY_IV);
			encryptor = rm.CreateEncryptor();
			byte[] encryptedDataWithoutIv = AesEncrypt(SAMPLE_ENCODED_DATA, encryptor);

			// 빈 IV 이용해서 복호화
			decryptor = rm.CreateDecryptor();
			byte[] decryptedDataWithoutIv = AesDecrypt(encryptedDataWithoutIv, decryptor);

			// 결과 출력
			Console.WriteLine($"Original Data:  {Convert.ToBase64String(SAMPLE_ENCODED_DATA)}");
			Console.WriteLine($"Decrypted Data: {Convert.ToBase64String(decryptedDataWithoutIv)}");

			//
			// 다른 언어에서 만든 키와 IV를 이용해서 복호화
			//
			for (int i = 1; i < aesFiles.Count; i++)
			{
				var otherFiles = aesFiles[i];
				
				if (!File.Exists(otherFiles.KeyFile) || !File.Exists(otherFiles.IvFile) || !File.Exists(otherFiles.EncryptedFile))
				{
					continue;
				}

				byte[] otherKeyData = Convert.FromBase64String(File.ReadAllText(otherFiles.KeyFile));
				byte[] otherIvData = Convert.FromBase64String(File.ReadAllText(otherFiles.IvFile));
				byte[] otherEncryptedData = Convert.FromBase64String(File.ReadAllText(otherFiles.EncryptedFile));
				RijndaelManaged otherRM = new RijndaelManaged()
				{
					KeySize = 256,
					BlockSize = 128,
					Mode = CipherMode.CBC,
					Padding = PaddingMode.PKCS7,
					Key = otherKeyData,
					IV = otherIvData
				};
				ICryptoTransform otherDecryptor = otherRM.CreateDecryptor();
				byte[] otherDecryptedData = AesDecrypt(otherEncryptedData, otherDecryptor);

				Console.WriteLine($"---------- AES, Language: {otherFiles.Language} ----------");
				Console.WriteLine($"Original Data : {Convert.ToBase64String(SAMPLE_ENCODED_DATA)}");
				Console.WriteLine($"Decrypted Data: {Convert.ToBase64String(otherDecryptedData)}");
			}
		}

		/// <summary>
		/// AES 키 또는 IV 생성
		/// </summary>
		/// <param name="size">리턴 받을 데이터 크기를 byte 단위로 지정</param>
		/// <returns></returns>
		private static byte[] AesCreateKey(int size)
		{
			RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
			byte[] password = new byte[AES_PASSWORD_SIZE];
			byte[] salt = new byte[AES_SALT_SIZE];
			rng.GetBytes(password);
			rng.GetBytes(salt);
			Rfc2898DeriveBytes keyGen = new Rfc2898DeriveBytes(password, salt, AES_ITERATION_COUNT);
			return keyGen.GetBytes(size);
		}

		private static byte[] AesEncrypt(byte[] data, ICryptoTransform encryptor)
		{
			byte[] result = null;
			using (MemoryStream ms = new MemoryStream())
			{
				using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
				{
					cs.Write(data, 0, data.Length);
				}
				result = ms.ToArray();
			}
			return result;
		}

		private static byte[] AesDecrypt(byte[] data, ICryptoTransform decryptor)
		{
			byte[] result = null;
			using (MemoryStream ms = new MemoryStream())
			{
				using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
				{
					cs.Write(data, 0, data.Length);
				}
				result = ms.ToArray();
			}
			return result;
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
