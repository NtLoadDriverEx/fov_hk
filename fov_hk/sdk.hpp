#pragma once
#include <cstdint>

struct fov_struct
{
	unsigned char gap0[8];
	float float8;
	unsigned char gapC[48];
	float float3C;
	float packed_fov;
};

using update_fov_fn = void*(__fastcall*)(fov_struct* fov);