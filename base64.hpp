#ifndef base64_h__
#define base64_h__
#include <string>
#include <iostream>
#include <ctype.h>

static const std::string g_base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

class base64 {
public:
	base64() = default;
	~base64() = default;

	inline std::string base64_encode(std::string const& input) {
		return base64_encode(
			reinterpret_cast<const unsigned char*>(input.data()),
			input.size()
		);
	}

	std::string base64_decode(const std::string& encoded_str) {
		size_t in_len = encoded_str.size();
		size_t i = 0;
		size_t index = 0;
		unsigned char array_4[4]{};
		unsigned char array_3[3]{};
		std::string ret;

		while (in_len-- && (encoded_str[index] != '=') && is_base64(encoded_str[index])) {
			array_4[i++] = encoded_str[index];
			index++;

			if (i == 4) {
				for (size_t index = 0; index < 4;index++) {
					array_4[index] = static_cast<unsigned char>(g_base64_chars.find(array_4[index]));
				}

				array_3[0] = (array_4[0] << 2) + ((array_4[1] & 0x30) >> 4);
				array_3[1] = ((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2);
				array_3[2] = ((array_4[2] & 0x3) << 6) + array_4[3];

				for (size_t index = 0;index < 3;index++) {
					ret += array_3[index];
				}

				i = 0;
			}
		}

		if (i) {
			for (size_t j = i; j < 4; j++) {
				array_4[j] = 0;
			}

			for (size_t j = 0; j < 4; j++) {
				array_4[j] = static_cast<unsigned char>(g_base64_chars.find(array_4[j]));
			}

			array_3[0] = (array_4[0] << 2) + ((array_4[1] & 0x30) >> 4);
			array_3[1] = ((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2);
			array_3[2] = ((array_4[2] & 0x3) << 6) + array_4[3];

			for (size_t j = 0;j < i - 1; j++) {
				ret += array_3[j];
			}
		}

		return std::move(ret);
	}

	inline bool is_base64(unsigned char c) {
		return (c == 43 || // +
			(c >= 47 && c <= 57) || // /-9
			(c >= 65 && c <= 90) || // A-Z
			(c >= 97 && c <= 122)); // a-z
	}
private:
	std::string base64_encode(const unsigned char* bytes_to_encode, size_t len) {
		std::string ret;
		int i = 0;
		size_t in_len = len;
		unsigned char array_3[3] = {};
		unsigned char array_4[4] = {};

		while (in_len--) {
			array_3[i++] = *(bytes_to_encode++);
			if (i == 3) {
				array_4[0] = (array_3[0] & 0xfc) >> 2;
				array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
				array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
				array_4[3] = array_3[2] & 0x3f;

				for (size_t index = 0;index < 4;index++) {
					ret += g_base64_chars[array_4[index]];
				}

				i = 0;
			}
		}

		if (i) {
			for (size_t j = i; j < 3; j++) {
				array_3[j] = '\0';
			}

			array_4[0] = (array_3[0] & 0xfc) >> 2;
			array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
			array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
			array_4[3] = array_3[2] & 0x3f;

			for (size_t j = 0;j < (i + 1); j++) {
				ret += g_base64_chars[array_4[j]];
			}

			while ((i++ < 3)) {
				ret += '=';
			}
		}

		return std::move(ret);
	}
};
#endif // base64_h__
