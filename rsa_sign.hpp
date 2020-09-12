#ifndef rsa_sign_h__
#define rsa_sign_h__

#include "base64.hpp"
#include <boost/beast/ssl.hpp>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

void split(std::vector<std::string>& result, const std::string& str, std::string demli) {
	std::string copy_str = str;
	char* ptr = strtok((char*)copy_str.c_str(), demli.c_str());
	while (ptr != nullptr) {
		result.push_back(std::move(ptr));
		ptr = strtok(nullptr, demli.c_str());
	}
}


class rsa_sign {
public:
	static rsa_sign& instance() {
		static rsa_sign instance;
		return instance;
	}

	bool init_cfg(std::string&& private_key_pah, std::string&& public_key_path = "") {
		std::ifstream file_read(private_key_pah, std::ios::ate | std::ios::binary);
		if (!file_read.is_open()) {
			return false;
		}

		std::size_t file_size = file_read.tellg();
		std::string data;
		data.resize(file_size);
		file_read.seekg(0, std::ios::beg);
		file_read.read(&data[0], file_size);
		file_read.close();

		size_t begin_pos = data.find_first_not_of("-----BEGIN RSA PRIVATE KEY-----", 0);
		if (begin_pos == std::string::npos) {
			return false;
		}

		size_t end_pos = data.find_last_not_of("-----END RSA PRIVATE KEY-----");
		if (end_pos == std::string::npos) {
			return false;
		}

		std::string copy_data = data.substr(begin_pos + 1, end_pos - begin_pos - 1);
		if (copy_data.empty()) {
			return false;
		}

		std::vector<std::string>res;
		split(res, copy_data, "\n");

		data.clear();
		auto iter_begin = res.begin();
		for (;iter_begin != res.end();++iter_begin) {
			data.append(std::move(*iter_begin));
		}

		if (data.empty()) {
			return false;
		}

		private_key_ = std::move(data);
		private_key_path_ = std::move(private_key_pah);
		public_key_path_ = std::move(public_key_path);
		return true;
	}

	std::string data_sign(const std::string& content) {
		int result = 0;
		unsigned int size = 0;
		std::string sign_str;
		std::string base64_str;
		EVP_PKEY* evp_key = nullptr;
		BIO* bufio = BIO_new(BIO_s_file());

		BIO_read_filename(bufio, private_key_path_.c_str());

		RSA* rsa = PEM_read_bio_RSAPrivateKey(bufio, NULL, NULL, NULL);
		if (rsa == nullptr) {
			std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
			goto safe_exit;
		}

		evp_key = EVP_PKEY_new();
		if (evp_key == nullptr) {
			std::cout << "EVP_PKEY_new failed" << std::endl;
			goto safe_exit;
		}

		if ((result = EVP_PKEY_set1_RSA(evp_key, rsa)) != 1) {
			std::cout << "EVP_PKEY_set1_RSA failed" << std::endl;
			goto safe_exit;
		}

		EVP_MD_CTX ctx;
		EVP_MD_CTX_init(&ctx);

		if ((result = EVP_SignInit_ex(&ctx, EVP_sha256(), NULL)) != 1) {
			std::cout << "EVP_SignInit_ex failed" << std::endl;
			goto safe_exit;
		}

		if ((result = EVP_SignUpdate(&ctx, content.c_str(), content.size())) != 1) {
			std::cout << "EVP_SignUpdate failed" << std::endl;
			goto safe_exit;
		}

		size = EVP_PKEY_size(evp_key);
		sign_str.resize(size);

		if ((result = EVP_SignFinal(&ctx, (unsigned char*)&sign_str[0], &size, evp_key)) != 1) {
			std::cout << "EVP_SignFinal failed" << std::endl;
			goto safe_exit;
		}

		base64_str = base64_.base64_encode(sign_str);
		EVP_MD_CTX_cleanup(&ctx);
	safe_exit:
		if (rsa != NULL) {
			RSA_free(rsa);
			rsa = NULL;
		}

		if (evp_key != NULL) {
			EVP_PKEY_free(evp_key);
			evp_key = NULL;
		}

		if (bufio != NULL) {
			BIO_free_all(bufio);
			bufio = NULL;
		}

		return std::move(base64_str);
	}

	std::string get_private_key() {
		std::string copy_str = private_key_;
		return std::move(copy_str);
	}

	bool verify_rsa(const std::string& content, const std::string& sign, const std::string& public_key_path) {
		BIO* bufio = BIO_new(BIO_s_file());
		BIO_read_filename(bufio, public_key_path.c_str());
		RSA* rsa = PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);

		bool verify = false;
		EVP_PKEY* evp_key = nullptr;

		EVP_MD_CTX ctx;
		int result = 0;
		std::string decoded_sign = base64_.base64_decode(sign);
		char* ch_de_sign = const_cast<char*>(decoded_sign.c_str());

		if (rsa == NULL) {
			std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
			goto safe_exit;
		}

		evp_key = EVP_PKEY_new();
		if (evp_key == NULL) {
			std::cout << "EVP_PKEY_new failed" << std::endl;
			goto safe_exit;
		}

		if ((result = EVP_PKEY_set1_RSA(evp_key, rsa)) != 1) {
			std::cout << "EVP_PKEY_set1_RSA failed" << std::endl;
			goto safe_exit;
		}

		EVP_MD_CTX_init(&ctx);

		if ((result = EVP_VerifyInit_ex(&ctx,
			EVP_sha256(), NULL)) != 1) {
			std::cout << "EVP_VerifyInit_ex failed" << std::endl;
			goto safe_exit;
		}

		if ((result = EVP_VerifyUpdate(&ctx,
			content.c_str(), content.size())) != 1) {
			std::cout << "EVP_VerifyUpdate failed" << std::endl;
			goto safe_exit;
		}

		if ((result = EVP_VerifyFinal(&ctx, (unsigned char*)ch_de_sign,
			static_cast<unsigned int>(decoded_sign.size()), evp_key)) != 1) {
			std::cout << "EVP_VerifyFinal failed" << std::endl;
			goto safe_exit;
		}

		if (result = 1) {
			verify = true;
		}

		EVP_MD_CTX_cleanup(&ctx);
	safe_exit:
		if (rsa != NULL) {
			RSA_free(rsa);
			rsa = NULL;
		}

		if (evp_key != NULL) {
			EVP_PKEY_free(evp_key);
			evp_key = NULL;
		}

		if (bufio != NULL) {
			BIO_free_all(bufio);
			bufio = NULL;
		}

		return verify;
	}

	std::string encrypt_data(const std::string& data) {
		std::string encrypt_msg;
		size_t rsa_size = 0;
		int ret = -1;
		size_t pos = 0;
		size_t block_len = 0;
		size_t data_size = data.size();
		BIO* bufio = BIO_new(BIO_s_file());
		BIO_read_filename(bufio, public_key_path_.c_str());
		RSA* rsa = PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);
		if (rsa == nullptr) {
			std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
			goto safe_exit;
		}

		rsa_size = RSA_size(rsa);
		block_len = rsa_size - 11;//因为填充方式为RSA_PKCS1_PADDING, 所以要在key_len基础上减去11
		while (pos < data_size) {
			std::string  encrypt_str;
			encrypt_str.resize(rsa_size);
			std::string  sub_str = data.substr(pos, block_len);
			ret = RSA_public_encrypt(
				static_cast<int>(sub_str.size()), (const unsigned char*)sub_str.c_str(),
				(unsigned char*)encrypt_str.data(), rsa, RSA_PKCS1_PADDING);

			if (ret == -1) {
				std::cout << "RSA_private_decrypt failed" << std::endl;
				goto safe_exit;
			}

			encrypt_str.resize(ret);
			encrypt_msg += std::move(encrypt_str);
			pos += block_len;

		}

		encrypt_msg = base64_.base64_encode(encrypt_msg);
	safe_exit:
		if (rsa != NULL) {
			RSA_free(rsa);
			rsa = NULL;
		}

		if (bufio != NULL) {
			BIO_free_all(bufio);
			bufio = NULL;
		}

		return std::move(encrypt_msg);
	}

	std::string decrypt_data(const std::string& encrypt_data) {
		std::string decrypt_msg;
		size_t size = 0;
		size_t rsa_size = 0;
		int ret = -1;
		size_t part_num = 0;
		unsigned char* encrypted_data = nullptr;
		BIO* bufio = BIO_new(BIO_s_file());
		BIO_read_filename(bufio, private_key_path_.c_str());
		RSA* rsa = PEM_read_bio_RSAPrivateKey(bufio, NULL, NULL, NULL);

		std::string decoded_base64_data = base64_.base64_decode(encrypt_data);
		if (rsa == NULL) {
			std::cout << "PEM_read_bio_RSA_PRIVATEKEY failed" << std::endl;
			goto safe_exit;
		}

		size = decoded_base64_data.size();
		rsa_size = RSA_size(rsa);

		part_num = size / rsa_size;
		encrypted_data = (unsigned char*)decoded_base64_data.data();

		for (size_t i = 0;i < part_num;++i) {
			std::string decrypted_str;
			decrypted_str.resize(rsa_size);

			ret = RSA_private_decrypt(
				static_cast<int>(rsa_size), encrypted_data + i * rsa_size,
				(unsigned char*)decrypted_str.data(), rsa, RSA_PKCS1_PADDING);

			if (ret == -1) {
				std::cout << "RSA_private_decrypt failed" << std::endl;
				goto safe_exit;
			}

			decrypted_str.resize(ret);
			decrypt_msg += std::move(decrypted_str);
		}
	safe_exit:
		if (rsa != NULL) {
			RSA_free(rsa);
			rsa = NULL;
		}

		if (bufio != NULL) {
			BIO_free_all(bufio);
			bufio = NULL;
		}

		return std::move(decrypt_msg);
	}

	std::string  sha256_hmac_hex(const std::string& key, const std::string& msg) {
		unsigned char hash[32] = { 0 };
		unsigned int len = 32;

		HMAC_CTX hmac;
		HMAC_CTX_init(&hmac);
		HMAC_Init_ex(&hmac, &key[0], static_cast<int>(key.size()), EVP_sha256(), NULL);
		HMAC_Update(&hmac, (unsigned char*)&msg[0], msg.size());
		HMAC_Final(&hmac, hash, &len);
		HMAC_CTX_cleanup(&hmac);

		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (size_t i = 0; i < len; i++) {
			ss << std::hex << std::setw(2) << (unsigned int)hash[i];
		}

		return std::move(ss.str());
	}

	rsa_sign(const rsa_sign&) = delete;
	rsa_sign& operator==(const rsa_sign&) = delete;
	rsa_sign(const rsa_sign&&) = delete;
	rsa_sign& operator==(const rsa_sign&&) = delete;
	~rsa_sign() {
		private_key_.clear();
	}
private:
	rsa_sign() = default;
private:
	std::string private_key_;
	std::string public_key_path_;
	std::string private_key_path_;
	base64 base64_;
};

#endif // rsa_sign_h__
