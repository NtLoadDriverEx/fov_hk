#pragma once
#include <array>
#include <vector>
#include <optional>
#include <algorithm>
#include <string>
#include <sstream>

namespace pattern
{
	namespace win
	{
		struct PEB_T
		{
			unsigned char   Reserved1[2];
			unsigned char   BeingDebugged;
			unsigned char   Reserved2[1];
			void* Mutant;
			uint64_t ImageBaseAddress;
		};

		struct IMAGE_DOS_HEADER // DOS .EXE header
		{
			unsigned short e_magic; // Magic number
			unsigned short e_cblp; // Bytes on last page of file
			unsigned short e_cp; // Pages in file
			unsigned short e_crlc; // Relocations
			unsigned short e_cparhdr; // Size of header in paragraphs
			unsigned short e_minalloc; // Minimum extra paragraphs needed
			unsigned short e_maxalloc; // Maximum extra paragraphs needed
			unsigned short e_ss; // Initial (relative) SS value
			unsigned short e_sp; // Initial SP value
			unsigned short e_csum; // Checksum
			unsigned short e_ip; // Initial IP value
			unsigned short e_cs; // Initial (relative) CS value
			unsigned short e_lfarlc; // File address of relocation table
			unsigned short e_ovno; // Overlay number
			unsigned short e_res[4]; // Reserved words
			unsigned short e_oemid; // OEM identifier (for e_oeminfo)
			unsigned short e_oeminfo; // OEM information; e_oemid specific
			unsigned short e_res2[10]; // Reserved words
			long           e_lfanew; // File address of new exe header
		};

		struct IMAGE_NT_HEADERS
		{
			unsigned long     Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER64 OptionalHeader;
		};

		inline const PEB_T* peb()
		{
			return reinterpret_cast<const win::PEB_T*>(__readgsqword(0x60));
		}

		inline const IMAGE_NT_HEADERS* nt_headers(uint64_t base) noexcept
		{
			return reinterpret_cast<const win::IMAGE_NT_HEADERS*>(
				base + reinterpret_cast<const win::IMAGE_DOS_HEADER*>(base)->e_lfanew);
		}
	}

	struct win_mod_info
	{
		uint8_t* start;
		uint8_t* end;
	};

	inline win_mod_info module_info()
	{
		const auto image_base = win::peb()->ImageBaseAddress;
		return { (uint8_t*)image_base, (uint8_t*)image_base + win::nt_headers(image_base)->OptionalHeader.SizeOfImage };
	}

	template<std::size_t N>
	auto scan(const char(&signature)[N], win_mod_info info) -> uint8_t*
	{
		auto split_fn = [](const std::string& to_split, char delim = ' ') -> std::vector<std::string>
		{
			std::vector<std::string> tokens;
			std::string token;
			std::istringstream token_stream{ to_split };
			while (std::getline(token_stream, token, delim))
				tokens.push_back(token);
			return tokens;
		};

		std::array<std::optional<uint8_t>, N> bytes{};

		auto split_signature = split_fn(signature);

		static constexpr auto wildcard = '?';
		std::transform(split_signature.cbegin(), split_signature.cend(), bytes.begin(),
			[](const std::string& str_hex_val) -> std::optional<uint8_t>
			{
				return str_hex_val.find(wildcard) == std::string::npos ? std::optional{ std::stoi(str_hex_val, 0, 16) } : std::nullopt;
			});

		auto [start, end] = info;

		auto found = std::search(start, end, bytes.cbegin(), bytes.cend(),
			[](uint8_t memory_byte, std::optional<uint8_t> signature_byte) -> bool
			{
				return signature_byte.value_or(memory_byte) == memory_byte;
			});

		if (found != end)
			return found;
		return nullptr;
	}

	template<std::size_t N>
	auto scan(const char(&signature)[N]) -> uint8_t*
	{
		return scan<N>(signature, module_info());
	}
}
