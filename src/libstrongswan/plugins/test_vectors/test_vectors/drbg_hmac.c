/*
 * Copyright (C) 2019 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the Licenseor (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be usefulbut
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <crypto/crypto_tester.h>

/**
 * NIST SP 800-90A DRBG HMAC Validation System (DRBGVS)
 */

/**
 * SHA-1 test case 1 - count 0
 */
drbg_test_vector_t drbg_hmac_sha1_1 = {
	.type = DRBG_HMAC_SHA1, .strength = 128,
	{ NULL, 0 },
	chunk_from_chars(0x79, 0x34, 0x9b, 0xbf, 0x7c, 0xdd, 0xa5, 0x79, 0x95, 0x57,
					 0x86, 0x66, 0x21, 0xc9, 0x13, 0x83, 0x11, 0x46, 0x73, 0x3a,
					 0xbf, 0x8c, 0x35, 0xc8, 0xc7, 0x21, 0x5b, 0x5b, 0x96, 0xc4,
					 0x8e, 0x9b, 0x33, 0x8c, 0x74, 0xe3, 0xe9, 0x9d, 0xfe, 0xdf),
	chunk_from_chars(0xc6, 0xa1, 0x6a, 0xb8, 0xd4, 0x20, 0x70, 0x6f, 0x0f, 0x34,
					 0xab, 0x7f, 0xec, 0x5a, 0xdc, 0xa9, 0xd8, 0xca, 0x3a, 0x13,
					 0x3e, 0x15, 0x9c, 0xa6, 0xac, 0x43, 0xc6, 0xf8, 0xa2, 0xbe,
					 0x22, 0x83, 0x4a, 0x4c, 0x0a, 0x0a, 0xff, 0xb1, 0x0d, 0x71,
					 0x94, 0xf1, 0xc1, 0xa5, 0xcf, 0x73, 0x22, 0xec, 0x1a, 0xe0,
					 0x96, 0x4e, 0xd4, 0xbf, 0x12, 0x27, 0x46, 0xe0, 0x87, 0xfd,
					 0xb5, 0xb3, 0xe9, 0x1b, 0x34, 0x93, 0xd5, 0xbb, 0x98, 0xfa,
					 0xed, 0x49, 0xe8, 0x5f, 0x13, 0x0f, 0xc8, 0xa4, 0x59, 0xb7)
};

/**
 * SHA-256 test case 1 - count 0
 */
drbg_test_vector_t drbg_hmac_sha256_1 = {
	.type = DRBG_HMAC_SHA256, .strength = 256,
	{ NULL, 0 },
	chunk_from_chars(0x06, 0x03, 0x2c, 0xd5, 0xee, 0xd3, 0x3f, 0x39, 0x26, 0x5f,
	                 0x49, 0xec, 0xb1, 0x42, 0xc5, 0x11, 0xda, 0x9a, 0xff, 0x2a,
	                 0xf7, 0x12, 0x03, 0xbf, 0xfa, 0xf3, 0x4a, 0x9c, 0xa5, 0xbd,
	                 0x9c, 0x0d, 0x0e, 0x66, 0xf7, 0x1e, 0xdc, 0x43, 0xe4, 0x2a,
					 0x45, 0xad, 0x3c, 0x6f, 0xc6, 0xcd, 0xc4, 0xdf, 0x01, 0x92,
					 0x0a, 0x4e, 0x66, 0x9e, 0xd3, 0xa8, 0x5a, 0xe8, 0xa3, 0x3b,
					 0x35, 0xa7, 0x4a, 0xd7, 0xfb, 0x2a, 0x6b, 0xb4, 0xcf, 0x39,
					 0x5c, 0xe0, 0x03, 0x34, 0xa9, 0xc9, 0xa5, 0xa5, 0xd5, 0x52),
	chunk_from_chars(0x76, 0xfc, 0x79, 0xfe, 0x9b, 0x50, 0xbe, 0xcc, 0xc9, 0x91,
					 0xa1, 0x1b, 0x56, 0x35, 0x78, 0x3a, 0x83, 0x53, 0x6a, 0xdd,
					 0x03, 0xc1, 0x57, 0xfb, 0x30, 0x64, 0x5e, 0x61, 0x1c, 0x28,
					 0x98, 0xbb, 0x2b, 0x1b, 0xc2, 0x15, 0x00, 0x02, 0x09, 0x20,
					 0x8c, 0xd5, 0x06, 0xcb, 0x28, 0xda, 0x2a, 0x51, 0xbd, 0xb0,
					 0x38, 0x26, 0xaa, 0xf2, 0xbd, 0x23, 0x35, 0xd5, 0x76, 0xd5,
					 0x19, 0x16, 0x08, 0x42, 0xe7, 0x15, 0x8a, 0xd0, 0x94, 0x9d,
					 0x1a, 0x9e, 0xc3, 0xe6, 0x6e, 0xa1, 0xb1, 0xa0, 0x64, 0xb0,
					 0x05, 0xde, 0x91, 0x4e, 0xac, 0x2e, 0x9d, 0x4f, 0x2d, 0x72,
					 0xa8, 0x61, 0x6a, 0x80, 0x22, 0x54, 0x22, 0x91, 0x82, 0x50,
					 0xff, 0x66, 0xa4, 0x1b, 0xd2, 0xf8, 0x64, 0xa6, 0xa3, 0x8c,
					 0xc5, 0xb6, 0x49, 0x9d, 0xc4, 0x3f, 0x7f, 0x2b, 0xd0, 0x9e,
					 0x1e, 0x0f, 0x8f, 0x58, 0x85, 0x93, 0x51, 0x24)
};

/**
 * SHA-256 test case 3 - count 0
 */
drbg_test_vector_t drbg_hmac_sha256_2 = {
	.type = DRBG_HMAC_SHA256, .strength = 256,
	chunk_from_chars(0xf2, 0xe5, 0x8f, 0xe6, 0x0a, 0x3a, 0xfc, 0x59, 0xda, 0xd3,
					 0x75, 0x95, 0x41, 0x5f, 0xfd, 0x31, 0x8c, 0xcf, 0x69, 0xd6,
					 0x77, 0x80, 0xf6, 0xfa, 0x07, 0x97, 0xdc, 0x9a, 0xa4, 0x3e,
					 0x14, 0x4c),
	chunk_from_chars(0xfa, 0x0e, 0xe1, 0xfe, 0x39, 0xc7, 0xc3, 0x90, 0xaa, 0x94,
					 0x15, 0x9d, 0x0d, 0xe9, 0x75, 0x64, 0x34, 0x2b, 0x59, 0x17,
					 0x77, 0xf3, 0xe5, 0xf6, 0xa4, 0xba, 0x2a, 0xea, 0x34, 0x2e,
					 0xc8, 0x40, 0xdd, 0x08, 0x20, 0x65, 0x5c, 0xb2, 0xff, 0xdb,
					 0x0d, 0xa9, 0xe9, 0x31, 0x0a, 0x67, 0xc9, 0xe5, 0xe0, 0x62,
					 0x9b, 0x6d, 0x79, 0x75, 0xdd, 0xfa, 0x96, 0xa3, 0x99, 0x64,
					 0x87, 0x40, 0xe6, 0x0f, 0x1f, 0x95, 0x57, 0xdc, 0x58, 0xb3,
					 0xd7, 0x41, 0x5f, 0x9b, 0xa9, 0xd4, 0xdb, 0xb5, 0x01, 0xf6),
	chunk_from_chars(0xf9, 0x2d, 0x4c, 0xf9, 0x9a, 0x53, 0x5b, 0x20, 0x22, 0x2a,
	 				 0x52, 0xa6, 0x8d, 0xb0, 0x4c, 0x5a, 0xf6, 0xf5, 0xff, 0xc7,
	 				 0xb6, 0x6a, 0x47, 0x3a, 0x37, 0xa2, 0x56, 0xbd, 0x8d, 0x29,
	 				 0x8f, 0x9b, 0x4a, 0xa4, 0xaf, 0x7e, 0x8d, 0x18, 0x1e, 0x02,
					 0x36, 0x79, 0x03, 0xf9, 0x3b, 0xdb, 0x74, 0x4c, 0x6c, 0x2f,
					 0x3f, 0x34, 0x72, 0x62, 0x6b, 0x40, 0xce, 0x9b, 0xd6, 0xa7,
					 0x0e, 0x7b, 0x8f, 0x93, 0x99, 0x2a, 0x16, 0xa7, 0x6f, 0xab,
					 0x6b, 0x5f, 0x16, 0x25, 0x68, 0xe0, 0x8e, 0xe6, 0xc3, 0xe8,
					 0x04, 0xae, 0xfd, 0x95, 0x2d, 0xdd, 0x3a, 0xcb, 0x79, 0x1c,
					 0x50, 0xf2, 0xad, 0x69, 0xe9, 0xa0, 0x40, 0x28, 0xa0, 0x6a,
					 0x9c, 0x01, 0xd3, 0xa6, 0x2a, 0xca, 0x2a, 0xaf, 0x6e, 0xfe,
					 0x69, 0xed, 0x97, 0xa0, 0x16, 0x21, 0x3a, 0x2d, 0xd6, 0x42,
					 0xb4, 0x88, 0x67, 0x64, 0x07, 0x2d, 0x9c, 0xbe)
};

/**
 * SHA-256 test case 5 - count 0
 */
drbg_test_vector_t drbg_hmac_sha256_3 = {
	.type = DRBG_HMAC_SHA256, .strength = 256,
	{ NULL, 0 },
	chunk_from_chars(0xff, 0x0c, 0xdd, 0x55, 0x5c, 0x60, 0x46, 0x47, 0x60, 0xb2,
					 0x89, 0xb7, 0xbc, 0x1f, 0x81, 0x1a, 0x41, 0xff, 0xf7, 0x2d,
					 0xe5, 0x90, 0x83, 0x85, 0x8c, 0x02, 0x0a, 0x10, 0x53, 0xbd,
					 0xc7, 0x4a, 0x7b, 0xc0, 0x99, 0x28, 0x5a, 0xd5, 0x62, 0x19,
					 0x93, 0xb6, 0x39, 0xc4, 0xa9, 0x4c, 0x37, 0x6b, 0x14, 0xfc,
					 0x6c, 0x9b, 0x17, 0x8d, 0xb6, 0x44, 0xa8, 0xcd, 0x71, 0x30,
					 0xa4, 0xcf, 0x05, 0x16, 0x78, 0xc8, 0xf4, 0xfa, 0x8f, 0x24,
					 0xc2, 0x7b, 0x0a, 0x53, 0x13, 0x38, 0xa5, 0xce, 0x85, 0x89),
	chunk_from_chars(0x2f, 0x26, 0x20, 0x34, 0x7b, 0xdd, 0xca, 0xa2, 0x94, 0x36,
					 0x85, 0x34, 0x6b, 0xbf, 0x31, 0xc4, 0x40, 0x81, 0xf8, 0x66,
					 0x5f, 0x3d, 0xdb, 0x2b, 0x42, 0xae, 0x14, 0x16, 0xa7, 0x4c,
					 0x4b, 0x77, 0xfa, 0xb3, 0xfa, 0x19, 0xae, 0xec, 0xc5, 0x47,
					 0xe7, 0x6c, 0x8c, 0xbe, 0x6a, 0xd1, 0xf1, 0x00, 0xa3, 0xfc,
					 0x8b, 0x2c, 0xe2, 0xa1, 0xea, 0x3a, 0x3d, 0xd7, 0xcf, 0xad,
					 0x46, 0xc1, 0xb2, 0x78, 0x30, 0xb9, 0x40, 0xba, 0x18, 0xd0,
					 0x9e, 0x9b, 0x7f, 0xa9, 0x02, 0xbb, 0x76, 0x06, 0x69, 0xb1,
					 0x73, 0x5c, 0xc7, 0xb7, 0xbd, 0x39, 0x05, 0x2d, 0xa7, 0xf2,
					 0x62, 0x6f, 0xa8, 0x70, 0x00, 0xcf, 0xfa, 0xda, 0x41, 0x00,
					 0x19, 0xd0, 0x53, 0x38, 0x6a, 0xd8, 0x08, 0xbd, 0x3c, 0x0c,
					 0xfc, 0xf5, 0x6b, 0x91, 0x87, 0x9e, 0xb8, 0xd3, 0xf9, 0x32,
					 0xee, 0x2d, 0x18, 0x5e, 0x54, 0xf3, 0x1b, 0x74)
};

/**
 * SHA-256 test case 7 - count 0
 */
drbg_test_vector_t drbg_hmac_sha256_4 = {
	.type = DRBG_HMAC_SHA256, .strength = 256,
	chunk_from_chars(0x40, 0x93, 0x3f, 0xdc, 0xce, 0x41, 0x59, 0xb0, 0x95, 0x51,
					 0x11, 0xf8, 0x44, 0x47, 0x1b, 0x0d, 0xb8, 0x5b, 0x73, 0xbd,
					 0xd2, 0xb7, 0x8c, 0x46, 0x8d, 0xd3, 0x9e, 0x2a, 0x9b, 0x29,
					 0xae, 0xf2),
	chunk_from_chars(0x28, 0xba, 0x1a, 0x66, 0x16, 0x32, 0xef, 0xc8, 0xec, 0xce,
					 0xd5, 0xf5, 0x1b, 0x79, 0x13, 0x00, 0xfb, 0x3b, 0x55, 0xb0,
					 0x5d, 0x04, 0x17, 0x08, 0x63, 0x8d, 0xe4, 0xbe, 0xb7, 0x57,
					 0xa9, 0xe5, 0x76, 0x82, 0x87, 0x96, 0xaf, 0xf0, 0x7f, 0x55,
					 0x79, 0x5c, 0xb5, 0x47, 0x13, 0xc7, 0x7e, 0xd4, 0xa5, 0xf5,
					 0x42, 0xb0, 0x4a, 0xaa, 0x5d, 0xbc, 0x93, 0x1e, 0x47, 0x01,
					 0x9f, 0xeb, 0x38, 0x96, 0x26, 0x16, 0xc5, 0x7a, 0xf0, 0x9b,
					 0x7c, 0x1d, 0xf8, 0x3f, 0x2b, 0x86, 0x0f, 0xf7, 0x65, 0x86),
	chunk_from_chars(0x65, 0xe5, 0xaa, 0x47, 0xb3, 0x85, 0xf1, 0xea, 0x42, 0xb2,
					 0x31, 0xb9, 0xfe, 0x74, 0x42, 0x53, 0xb8, 0x59, 0x88, 0x59,
					 0xd7, 0x01, 0x1e, 0x52, 0x5f, 0x5a, 0x2a, 0x1a, 0xd3, 0x2a,
					 0x97, 0x2a, 0x85, 0x08, 0x02, 0xc6, 0x0a, 0x2b, 0xe1, 0x9b,
					 0xe2, 0x70, 0x06, 0x3a, 0x3c, 0xfb, 0xea, 0xae, 0x95, 0x4f,
					 0x10, 0xb1, 0x22, 0x35, 0x2d, 0xe6, 0xa0, 0x8a, 0xc4, 0x10,
					 0xe0, 0x99, 0x16, 0x53, 0xaa, 0xb2, 0x71, 0xb3, 0x60, 0xfe,
					 0x91, 0x91, 0xcf, 0x5a, 0xdd, 0xcc, 0xcc, 0xed, 0x8c, 0x4a,
					 0xcf, 0xb6, 0x14, 0x57, 0x04, 0x99, 0x92, 0x98, 0x8f, 0xd7,
					 0xa9, 0xac, 0xca, 0x1f, 0x1b, 0xca, 0x35, 0xf1, 0x47, 0x58,
					 0x13, 0x69, 0x4a, 0x39, 0x98, 0x8e, 0x5f, 0xac, 0x9f, 0x4a,
					 0xc0, 0x57, 0x22, 0x86, 0xbc, 0x46, 0x25, 0x82, 0xad, 0x0a,
					 0xf7, 0x8a, 0xb3, 0xb8, 0x5e, 0xc1, 0x7a, 0x25)
};

/**
 * SHA-256 test case 9 - count 0
 */
drbg_test_vector_t drbg_hmac_sha256_5 = {
	.type = DRBG_HMAC_SHA256, .strength = 256,
	{ NULL, 0 },
	chunk_from_chars(0x6a, 0xe8, 0x03, 0x03, 0x29, 0x23, 0x91, 0x33, 0x5b, 0xf9,
					 0xc9, 0x38, 0x7f, 0xbd, 0x3b, 0xf6, 0x15, 0x75, 0x6c, 0x9c,
					 0x27, 0xc3, 0x47, 0x8c, 0x87, 0xe2, 0x60, 0xcf, 0x97, 0xd4,
					 0x71, 0x10, 0x01, 0xe1, 0x62, 0x47, 0xdd, 0x4c, 0xae, 0x64,
					 0x99, 0x33, 0x7d, 0x82, 0x78, 0x4e, 0xa5, 0x7f, 0x03, 0x57,
					 0x02, 0xef, 0x4e, 0x11, 0x2b, 0x17, 0x31, 0x12, 0xc5, 0x85,
					 0x1d, 0x07, 0xb2, 0x79, 0x30, 0x98, 0x63, 0x74, 0x0d, 0x38,
					 0xd0, 0xd0, 0x72, 0x02, 0x23, 0xe2, 0x40, 0x17, 0xbb, 0xc0),
	chunk_from_chars(0xcf, 0x43, 0x15, 0x59, 0x8f, 0xcd, 0x6a, 0xf1, 0x31, 0x55,
					 0x18, 0xc4, 0xbf, 0xba, 0xc0, 0x54, 0x0c, 0x58, 0x96, 0x35,
					 0x27, 0x35, 0x48, 0xa7, 0xb5, 0x07, 0xe7, 0xd2, 0xe6, 0x85,
					 0xe5, 0x94, 0x7b, 0x87, 0xae, 0x25, 0x7e, 0x58, 0xfa, 0xf2,
					 0x14, 0xf2, 0xb5, 0x8e, 0xd1, 0x0c, 0x3b, 0xd3, 0x5f, 0x75,
					 0xf6, 0xc3, 0x5d, 0xd6, 0xd4, 0x41, 0xc9, 0x3b, 0xcd, 0x42,
					 0xe7, 0x17, 0x20, 0x10, 0x26, 0x31, 0xb1, 0xa6, 0xa4, 0xba,
					 0x24, 0x7c, 0x17, 0x5e, 0xd8, 0x00, 0xcf, 0xca, 0x6e, 0x1e,
					 0x83, 0x9b, 0x5a, 0xa9, 0x07, 0x60, 0x4c, 0xcf, 0xe6, 0xf9,
					 0x84, 0xf6, 0x82, 0x2e, 0x00, 0x1a, 0xb0, 0x2d, 0xd6, 0x63,
					 0x49, 0x64, 0xf7, 0x89, 0xcb, 0x10, 0x7a, 0x97, 0x73, 0x46,
					 0x69, 0x3f, 0x32, 0x44, 0xc8, 0x95, 0xe8, 0x40, 0xdf, 0xa0,
					 0xed, 0xf7, 0xf1, 0x4d, 0xc6, 0x1d, 0x79, 0x4f)
};

/**
 * SHA-256 test case 11 - count 0
 */
drbg_test_vector_t drbg_hmac_sha256_6 = {
	.type = DRBG_HMAC_SHA256, .strength = 256,
	chunk_from_chars(0x9f, 0x16, 0x99, 0xc9, 0x9d, 0x60, 0xb0, 0x85, 0xbc, 0x61,
					 0xcb, 0x11, 0x0e, 0xf8, 0xab, 0x59, 0x0d, 0x82, 0xa9, 0x70,
					 0x02, 0x1c, 0x3c, 0x6a, 0x5d, 0x48, 0x02, 0x1c, 0x45, 0xde,
					 0x49, 0x56),
	chunk_from_chars(0x63, 0x3d, 0x32, 0xe3, 0x00, 0x5f, 0x78, 0x11, 0x47, 0x23,
					 0xb3, 0xea, 0x5a, 0xc1, 0x21, 0xba, 0x74, 0xaa, 0x00, 0xc5,
					 0x2d, 0x93, 0x96, 0x67, 0xe3, 0x0c, 0x33, 0x51, 0xb3, 0x85,
					 0x49, 0xf7, 0x37, 0xaf, 0xff, 0x50, 0x4a, 0x2d, 0x8a, 0xc1,
					 0x68, 0xc6, 0x8e, 0x24, 0xd0, 0xfe, 0x66, 0xf6, 0x3e, 0x33,
					 0x47, 0xc5, 0x47, 0xf1, 0x7f, 0x4d, 0x0b, 0x9f, 0x46, 0x40,
					 0x5a, 0x54, 0xee, 0xdd, 0x7e, 0x98, 0x0d, 0x06, 0xa2, 0x15,
					 0xec, 0x15, 0xe8, 0x93, 0x16, 0xab, 0x74, 0x3b, 0x75, 0x47),
	chunk_from_chars(0x6e, 0x38, 0xe8, 0x29, 0x62, 0xd7, 0x07, 0xce, 0x9a, 0x6a,
					 0xc3, 0x83, 0xa7, 0x38, 0xa7, 0x48, 0xf9, 0x75, 0xeb, 0x78,
					 0x56, 0x11, 0xfa, 0xd5, 0xe3, 0xf5, 0xa4, 0xfe, 0x44, 0xd7,
					 0xb5, 0x9a, 0x98, 0x13, 0x7a, 0x2b, 0xcd, 0xc3, 0x5f, 0x9e,
					 0xe9, 0xa1, 0xe2, 0x1b, 0xb1, 0x7d, 0xf1, 0x66, 0x5c, 0xd1,
					 0x39, 0x76, 0x25, 0xa1, 0x77, 0x24, 0x7e, 0x2e, 0x32, 0x9a,
					 0x66, 0x01, 0x40, 0x63, 0x61, 0x41, 0x56, 0x06, 0x10, 0xa3,
					 0x68, 0xbf, 0xd4, 0x99, 0xc2, 0xe2, 0x5b, 0xe3, 0x18, 0xaa,
					 0x4d, 0xa9, 0xe7, 0xa3, 0x52, 0xd1, 0x15, 0xdb, 0x82, 0x82,
					 0xed, 0x8d, 0x79, 0xec, 0xf9, 0xcd, 0x82, 0x03, 0x60, 0xd3,
					 0xd2, 0xd1, 0xa5, 0x8a, 0x93, 0xe0, 0x40, 0xf5, 0x55, 0x48,
					 0x87, 0xce, 0x6c, 0x98, 0x58, 0xbc, 0x2b, 0xb1, 0x02, 0x24,
					 0x99, 0x80, 0xa8, 0x58, 0x49, 0x8a, 0xbc, 0xda)
};

/**
 * SHA-512 test case 1 - count 0
 */
drbg_test_vector_t drbg_hmac_sha512_1 = {
	.type = DRBG_HMAC_SHA512, .strength = 256,
	{ NULL, 0 },
	chunk_from_chars(0x48, 0xc1, 0x21, 0xb1, 0x87, 0x33, 0xaf, 0x15, 0xc2, 0x7e,
					 0x1d, 0xd9, 0xba, 0x66, 0xa9, 0xa8, 0x1a, 0x55, 0x79, 0xcd,
					 0xba, 0x0f, 0x5b, 0x65, 0x7e, 0xc5, 0x3c, 0x2b, 0x9e, 0x90,
					 0xbb, 0xf6, 0xbb, 0xb7, 0xc7, 0x77, 0x42, 0x80, 0x68, 0xfa,
					 0xd9, 0x97, 0x08, 0x91, 0xf8, 0x79, 0xb1, 0xaf, 0xe0, 0xff,
					 0xef, 0xda, 0xdb, 0x9c, 0xcf, 0x99, 0x05, 0x04, 0xd5, 0x68,
					 0xbd, 0xb4, 0xd8, 0x62, 0xcb, 0xe1, 0x7c, 0xcc, 0xe6, 0xe2,
					 0x2d, 0xfc, 0xab, 0x8b, 0x48, 0x04, 0xfd, 0x21, 0x42, 0x1a),
	chunk_from_chars(0x05, 0xda, 0x6a, 0xac, 0x7d, 0x98, 0x0d, 0xa0, 0x38, 0xf6,
					 0x5f, 0x39, 0x28, 0x41, 0x47, 0x6d, 0x37, 0xfe, 0x70, 0xfb,
					 0xd3, 0xe3, 0x69, 0xd1, 0xf8, 0x01, 0x96, 0xe6, 0x6e, 0x54,
					 0xb8, 0xfa, 0xdb, 0x1d, 0x60, 0xe1, 0xa0, 0xf3, 0xd4, 0xdc,
					 0x17, 0x37, 0x69, 0xd7, 0x5f, 0xc3, 0x41, 0x05, 0x49, 0xd7,
					 0xa8, 0x43, 0x27, 0x0a, 0x54, 0xa0, 0x68, 0xb4, 0xfe, 0x76,
					 0x7d, 0x7d, 0x9a, 0x59, 0x60, 0x45, 0x10, 0xa8, 0x75, 0xad,
					 0x1e, 0x97, 0x31, 0xc8, 0xaf, 0xd0, 0xfd, 0x50, 0xb8, 0x25,
					 0xe2, 0xc5, 0x0d, 0x06, 0x25, 0x76, 0x17, 0x51, 0x06, 0xa9,
					 0x98, 0x1b, 0xe3, 0x7e, 0x02, 0xec, 0x7c, 0x5c, 0xd0, 0xa6,
					 0x9a, 0xa0, 0xca, 0x65, 0xbd, 0xda, 0xee, 0x1b, 0x0d, 0xe5,
					 0x32, 0xe1, 0x0c, 0xfa, 0x1f, 0x5b, 0xf6, 0xa0, 0x26, 0xe4,
					 0x73, 0x79, 0x73, 0x6a, 0x09, 0x9d, 0x67, 0x50, 0xab, 0x12,
					 0x1d, 0xbe, 0x36, 0x22, 0xb8, 0x41, 0xba, 0xf8, 0xbd, 0xcb,
					 0xe8, 0x75, 0xc8, 0x5b, 0xa4, 0xb5, 0x86, 0xb8, 0xb5, 0xb5,
					 0x7b, 0x0f, 0xec, 0xbe, 0xc0, 0x8c, 0x12, 0xff, 0x2a, 0x94,
					 0x53, 0xc4, 0x7c, 0x6e, 0x32, 0xa5, 0x21, 0x03, 0xd9, 0x72,
					 0xc6, 0x2a, 0xb9, 0xaf, 0xfb, 0x8e, 0x72, 0x8a, 0x31, 0xfc,
					 0xef, 0xbb, 0xcc, 0xc5, 0x56, 0xc0, 0xf0, 0xa3, 0x5f, 0x4b,
					 0x10, 0xac, 0xe2, 0xd9, 0x6b, 0x90, 0x6e, 0x36, 0xcb, 0xb7,
					 0x22, 0x33, 0x20, 0x1e, 0x53, 0x6d, 0x3e, 0x13, 0xb0, 0x45,
					 0x18, 0x7b, 0x41, 0x7d, 0x24, 0x49, 0xca, 0xd1, 0xed, 0xd1,
					 0x92, 0xe0, 0x61, 0xf1, 0x2d, 0x22, 0x14, 0x7b, 0x0a, 0x17,
					 0x6e, 0xa8, 0xd9, 0xc4, 0xc3, 0x54, 0x04, 0x39, 0x5b, 0x65,
					 0x02, 0xef, 0x33, 0x3a, 0x81, 0x3b, 0x65, 0x86, 0x03, 0x74,
					 0x79, 0xe0, 0xfa, 0x3c, 0x6a, 0x23)
};